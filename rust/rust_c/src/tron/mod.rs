pub mod structs;

use crate::common::errors::RustCError;
use crate::common::keystone;
use crate::common::structs::{SimpleResponse, TransactionCheckResult, TransactionParseResult};
use crate::common::types::{PtrBytes, PtrString, PtrT, PtrUR};
use crate::common::ur::{QRCodeType, UREncodeResult};
use crate::common::utils::{convert_c_char, recover_c_char};
use alloc::boxed::Box;
use alloc::slice;
use alloc::vec;
use cty::c_char;
use hex;
use structs::DisplayTron;

#[no_mangle]
pub extern "C" fn tron_check_keystone(
    ptr: PtrUR,
    ur_type: QRCodeType,
    master_fingerprint: PtrBytes,
    length: u32,
    x_pub: PtrString,
) -> PtrT<TransactionCheckResult> {
    keystone::check(ptr, ur_type, master_fingerprint, length, x_pub)
}

#[no_mangle]
pub extern "C" fn tron_parse_keystone(
    ptr: PtrUR,
    ur_type: QRCodeType,
    master_fingerprint: PtrBytes,
    length: u32,
    x_pub: PtrString,
) -> *mut TransactionParseResult<DisplayTron> {
    if length != 4 {
        return TransactionParseResult::from(RustCError::InvalidMasterFingerprint).c_ptr();
    }
    keystone::build_payload(ptr, ur_type).map_or_else(
        |e| TransactionParseResult::from(e).c_ptr(),
        |payload| {
            keystone::build_parse_context(master_fingerprint, x_pub).map_or_else(
                |e| TransactionParseResult::from(e).c_ptr(),
                |context| {
                    app_tron::parse_raw_tx(payload, context).map_or_else(
                        |e| TransactionParseResult::from(e).c_ptr(),
                        |res| {
                            TransactionParseResult::success(Box::into_raw(Box::new(
                                DisplayTron::from(res),
                            )))
                            .c_ptr()
                        },
                    )
                },
            )
        },
    )
}
#[no_mangle]
pub extern "C" fn tron_parse_keystone_raw(
    ptr: PtrUR,
    ur_type: QRCodeType,
) -> *mut SimpleResponse<c_char> {
    crate::log::log_message("Entering tron_parse_keystone_raw");
    keystone::build_payload(ptr, ur_type).map_or_else(
        |e| {
            return SimpleResponse::from(e).simple_c_ptr();
        },
        |payload| {
            app_tron::get_wrapped_tron_tx(payload).map_or_else(
                |e| SimpleResponse::from(e).simple_c_ptr(),
                |res| {
                    let tx_bytes = match res.raw_tx_bytes() {
                        Ok(bytes) => {
                            return SimpleResponse::success(
                                convert_c_char(hex::encode(bytes)) as *mut c_char
                            )
                            .simple_c_ptr();
                        }
                        Err(e) => {
                            return SimpleResponse::from(e).simple_c_ptr();
                        }
                    };
                },
            )
        },
    )
}

#[no_mangle]
pub extern "C" fn tron_parse_keystone_path(
    ptr: PtrUR,
    ur_type: QRCodeType,
) -> *mut SimpleResponse<c_char> {
    keystone::build_payload(ptr, ur_type).map_or_else(
        |e| {
            return SimpleResponse::from(e).simple_c_ptr();
        },
        |payload| {
            app_tron::get_wrapped_tron_tx(payload).map_or_else(
                |e| {
                    return SimpleResponse::from(e).simple_c_ptr();
                },
                |res| {
                    SimpleResponse::success(convert_c_char(res.hd_path) as *mut c_char)
                        .simple_c_ptr()
                },
            )
        },
    )
}

#[no_mangle]
pub extern "C" fn tron_encode_signature(
    ptr: PtrUR,
    ur_type: QRCodeType,
    signature: PtrBytes,
    signature_len: u32,
) -> PtrT<UREncodeResult> {
    keystone::build_payload(ptr, ur_type).map_or_else(
        |e| {
            return UREncodeResult::from(e).c_ptr();
        },
        |payload| {
            let payload_clone = payload.clone();
            app_tron::get_wrapped_tron_tx(payload).map_or_else(
                |e| {
                    return UREncodeResult::from(e).c_ptr();
                },
                |mut wrapped_tron| {
                    let signature =
                        unsafe { slice::from_raw_parts(signature, signature_len as usize) };
                    let count: usize = wrapped_tron
                        .tron_tx
                        .raw_data
                        .as_ref()
                        .map_or(0, |raw_data| raw_data.contract.len());
                    wrapped_tron.tron_tx.signature = vec![signature.to_vec(); count];
                    let tx_raw = hex::encode(wrapped_tron.encode_to_vec());
                    let tx_id = match wrapped_tron.signature_hash() {
                        Ok(hash) => hex::encode(hash),
                        Err(e) => {
                            return UREncodeResult::from(e).c_ptr();
                        }
                    };

                    return keystone::build_sign_result_with_raw(
                        payload_clone,
                        tx_raw,
                        tx_id,
                        0x100,
                    );
                },
            )
        },
    )
}

#[no_mangle]
pub extern "C" fn tron_sign_keystone(
    ptr: PtrUR,
    ur_type: QRCodeType,
    master_fingerprint: PtrBytes,
    length: u32,
    x_pub: PtrString,
    cold_version: i32,
    seed: PtrBytes,
    seed_len: u32,
) -> *mut UREncodeResult {
    let seed = unsafe { slice::from_raw_parts(seed, seed_len as usize) };
    keystone::sign(
        ptr,
        ur_type,
        master_fingerprint,
        length,
        x_pub,
        cold_version,
        seed,
    )
}

#[no_mangle]
pub extern "C" fn tron_get_address(
    hd_path: PtrString,
    x_pub: PtrString,
) -> *mut SimpleResponse<c_char> {
    let x_pub = recover_c_char(x_pub);
    let hd_path = recover_c_char(hd_path);
    let address = app_tron::get_address(hd_path, &x_pub);
    match address {
        Ok(result) => SimpleResponse::success(convert_c_char(result) as *mut c_char).simple_c_ptr(),
        Err(e) => SimpleResponse::from(e).simple_c_ptr(),
    }
}
