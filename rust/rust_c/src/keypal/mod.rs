use crate::common::errors::ErrorCodes;
use crate::common::free::Free;
use crate::common::structs::Response;
use crate::common::structs::SimpleResponse;
use crate::common::types::{PtrBytes, PtrString, PtrT, PtrUR};
use crate::common::ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT};
use crate::common::utils::{convert_c_char, recover_c_char};
use crate::extract_ptr_with_type;
use crate::{free_str_ptr, free_vec, impl_c_ptr, make_free_method};
use alloc::format;
use alloc::slice;
use alloc::string::{String, ToString};
use cty::c_char;
use serde;
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

#[derive(serde::Serialize, serde::Deserialize)]
pub struct MnemonicData {
    mn: String,
    lang: String,
    ph: String,
}

pub fn keypal_card_mnemonic_serialize(data: MnemonicData) -> String {
    serde_json::to_string(&data).unwrap_or_default()
}
pub fn keypal_card_mnemonic_deserialize(data: String) -> Result<MnemonicData, serde_json::Error> {
    serde_json::from_str::<MnemonicData>(&data)
}

#[repr(C)]
pub struct KeypalMnemonicData {
    pub mn: PtrString,
    pub lang: PtrString,
    pub ph: PtrString,
}

impl From<MnemonicData> for KeypalMnemonicData {
    fn from(data: MnemonicData) -> Self {
        KeypalMnemonicData {
            mn: convert_c_char(data.mn),
            lang: convert_c_char(data.lang),
            ph: convert_c_char(data.ph),
        }
    }
}

impl Free for KeypalMnemonicData {
    fn free(&self) {
        free_str_ptr!(self.mn);
        free_str_ptr!(self.lang);
        free_str_ptr!(self.ph);
    }
}
impl_c_ptr!(KeypalMnemonicData);
make_free_method!(Response<KeypalMnemonicData>);

#[no_mangle]
pub extern "C" fn keypal_card_deserialize_mnemonic(
    data: PtrString,
) -> *mut Response<KeypalMnemonicData> {
    let data_str = recover_c_char(data);
    match keypal_card_mnemonic_deserialize(data_str) {
        Ok(mnemonic_data) => {
            let c_mnemonic_data: KeypalMnemonicData = mnemonic_data.into();
            Response::success(c_mnemonic_data).c_ptr()
        }
        Err(_) => Response::error(ErrorCodes::InvalidData, String::new()).c_ptr(),
    }
}

#[no_mangle]
pub extern "C" fn keypal_card_serialize_mnemonic(
    mn: PtrString,
    lang: PtrString,
    ph: PtrString,
) -> *mut SimpleResponse<c_char> {
    let mn_str = recover_c_char(mn);
    let lang_str = recover_c_char(lang);
    let ph_str = recover_c_char(ph);
    let mnemonic_data = MnemonicData {
        mn: mn_str,
        lang: lang_str,
        ph: ph_str,
    };
    let serialized_str = keypal_card_mnemonic_serialize(mnemonic_data);
    SimpleResponse::success(convert_c_char(serialized_str) as *mut c_char).simple_c_ptr()
}
