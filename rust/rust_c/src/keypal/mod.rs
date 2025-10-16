use crate::common::structs::SimpleResponse;
use crate::common::types::{PtrBytes, PtrString, PtrT, PtrUR};
use crate::common::ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT};
use crate::common::utils::{convert_c_char, recover_c_char};
use crate::extract_ptr_with_type;
use alloc::slice;
use cty::c_char;
use rsa::signature;
use ur_registry::keypal::keypal_device_info::KeypalDeviceInfo;
use ur_registry::keypal::keypal_device_signature::KeypalDeviceSignature;
use ur_registry::keypal::keypal_device_verify_request::KeypalDeviceVerifyRequest;
use ur_registry::traits::RegistryItem;
#[no_mangle]
pub extern "C" fn keypal_ur_encode_device_info(
    features: PtrBytes,
    features_len: u32,
    certificate: PtrString,
) -> PtrT<UREncodeResult> {
    let features = unsafe { slice::from_raw_parts(features, features_len as usize) };
    let eth_signature = KeypalDeviceInfo::new(features.to_vec(), recover_c_char(certificate));
    match eth_signature.try_into() {
        Err(e) => UREncodeResult::from(e).c_ptr(),
        Ok(v) => UREncodeResult::encode(
            v,
            KeypalDeviceInfo::get_registry_type().get_type(),
            FRAGMENT_MAX_LENGTH_DEFAULT,
        )
        .c_ptr(),
    }
}
#[no_mangle]
pub extern "C" fn keypal_ur_encode_device_verify_request(
    request_id: PtrBytes,
    request_id_len: u32,
    sign_data: PtrBytes,
    sign_data_len: u32,
) -> PtrT<UREncodeResult> {
    let request_id = unsafe { slice::from_raw_parts(request_id, request_id_len as usize) };
    let sign_data = unsafe { slice::from_raw_parts(sign_data, sign_data_len as usize) };
    let request = KeypalDeviceVerifyRequest::new(request_id.to_vec(), sign_data.to_vec());
    match request.try_into() {
        Err(e) => UREncodeResult::from(e).c_ptr(),
        Ok(v) => UREncodeResult::encode(
            v,
            KeypalDeviceVerifyRequest::get_registry_type().get_type(),
            FRAGMENT_MAX_LENGTH_DEFAULT,
        )
        .c_ptr(),
    }
}

#[no_mangle]
pub extern "C" fn keypal_parse_device_verify_request(ptr: PtrUR) -> *mut SimpleResponse<c_char> {
    let v = extract_ptr_with_type!(ptr, KeypalDeviceVerifyRequest);
    let sign_data_hex = hex::encode(v.get_sign_data());
    SimpleResponse::success(convert_c_char(sign_data_hex) as *mut c_char).simple_c_ptr()
}

#[no_mangle]
pub extern "C" fn keypal_ur_encode_device_signature(
    ptr: PtrUR,
    signature: PtrBytes,
    signature_len: u32,
) -> *mut UREncodeResult {
    let v = extract_ptr_with_type!(ptr, KeypalDeviceVerifyRequest);
    let request_id = v.get_request_id();
    let signature = unsafe { slice::from_raw_parts(signature, signature_len as usize) }.to_vec();
    let signature = KeypalDeviceSignature::new(request_id, signature);
    match signature.try_into() {
        Err(e) => UREncodeResult::from(e).c_ptr(),
        Ok(v) => UREncodeResult::encode(
            v,
            KeypalDeviceSignature::get_registry_type().get_type(),
            FRAGMENT_MAX_LENGTH_DEFAULT,
        )
        .c_ptr(),
    }
}
