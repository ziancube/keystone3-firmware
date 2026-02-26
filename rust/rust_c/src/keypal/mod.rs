use crate::common::errors::ErrorCodes;
use crate::common::errors::RustCError;
use crate::common::free::Free;
use crate::common::structs::Response;
use crate::common::structs::{SimpleResponse, TransactionCheckResult, TransactionParseResult};
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
use ur_registry::keypal::keypal_tron_sign_request::KeypalTronSignRequest;
use ur_registry::keypal::keypal_tron_signature::KeypalTronSignature;
use ur_registry::traits::RegistryItem;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ffi::{c_uchar, c_ulong};
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

#[no_mangle]
pub extern "C" fn keypal_tron_get_path(ptr: PtrUR) -> PtrString {
    let tron_sign_request = extract_ptr_with_type!(ptr, KeypalTronSignRequest);
    let derivation_path = tron_sign_request.get_derivation_path();
    if let Some(path) = derivation_path.get_path() {
        let formatted_path = if path.starts_with("m/") {
            path
        } else {
            format!("m/{}", path)
        };
        return convert_c_char(formatted_path);
    }
    convert_c_char("".to_string())
}

#[no_mangle]
pub extern "C" fn keypal_tron_parse_tx_raw(ptr: PtrUR) -> PtrString {
    let tron_sign_request = extract_ptr_with_type!(ptr, KeypalTronSignRequest);
    let tx_hex = tron_sign_request.get_sign_data();
    convert_c_char(hex::encode(tx_hex))
}

#[no_mangle]
pub extern "C" fn keypal_tron_ur_encode_signature(
    ptr: PtrUR,
    signature: PtrBytes,
    signature_len: u32,
) -> PtrT<UREncodeResult> {
    let crypto_tron = extract_ptr_with_type!(ptr, KeypalTronSignRequest);
    let signature = unsafe { slice::from_raw_parts(signature, signature_len as usize) };
    let tron_signature = KeypalTronSignature::new(crypto_tron.get_request_id(), signature.to_vec());
    match tron_signature.try_into() {
        Err(e) => UREncodeResult::from(e).c_ptr(),
        Ok(v) => UREncodeResult::encode(
            v,
            KeypalTronSignature::get_registry_type().get_type(),
            FRAGMENT_MAX_LENGTH_DEFAULT,
        )
        .c_ptr(),
    }
}
#[no_mangle]
pub extern "C" fn keypal_tron_check(
    ptr: PtrUR,
    master_fingerprint: PtrBytes,
    length: u32,
) -> PtrT<TransactionCheckResult> {
    if length != 4 {
        return TransactionCheckResult::from(RustCError::InvalidMasterFingerprint).c_ptr();
    }
    let sol_sign_request = extract_ptr_with_type!(ptr, KeypalTronSignRequest);
    let mfp = unsafe { core::slice::from_raw_parts(master_fingerprint, 4) };
    if let Ok(mfp) = (mfp.try_into() as Result<[u8; 4], _>) {
        let derivation_path: ur_registry::crypto_key_path::CryptoKeyPath =
            sol_sign_request.get_derivation_path();
        if let Some(ur_mfp) = derivation_path.get_source_fingerprint() {
            return if mfp == ur_mfp {
                TransactionCheckResult::new().c_ptr()
            } else {
                TransactionCheckResult::from(RustCError::MasterFingerprintMismatch).c_ptr()
            };
        }
        return TransactionCheckResult::from(RustCError::MasterFingerprintMismatch).c_ptr();
    };
    TransactionCheckResult::from(RustCError::InvalidMasterFingerprint).c_ptr()
}

/// 暴露给 C 的不透明类型：**只作为指针使用**
#[repr(C)]
pub struct RustVecU8 {
    _private: [u8; 0],
}

// 一些内部小工具函数：在指针层面把 RustVecU8 <-> Vec<u8> 互相转换
#[inline]
unsafe fn as_vec_mut<'a>(ptr: *mut RustVecU8) -> &'a mut Vec<u8> {
    &mut *(ptr as *mut Vec<u8>)
}

#[inline]
unsafe fn as_vec_ref<'a>(ptr: *const RustVecU8) -> &'a Vec<u8> {
    &*(ptr as *const Vec<u8>)
}

/// 创建一个空 Vec<u8>
#[no_mangle]
pub extern "C" fn vec_u8_new() -> *mut RustVecU8 {
    let v: Vec<u8> = Vec::new();
    Box::into_raw(Box::new(v)) as *mut RustVecU8
}

/// 创建一个带初始容量的 Vec<u8>
#[no_mangle]
pub extern "C" fn vec_u8_with_capacity(cap: c_ulong) -> *mut RustVecU8 {
    let v: Vec<u8> = Vec::with_capacity(cap as usize);
    Box::into_raw(Box::new(v)) as *mut RustVecU8
}

/// 释放 Vec<u8>
#[no_mangle]
pub extern "C" fn vec_u8_free(ptr: *mut RustVecU8) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        // 把 pointer 当成 Box<Vec<u8>> 拿回来，drop 掉
        let _ = Box::from_raw(ptr as *mut Vec<u8>);
    }
}

/// 获取长度
#[no_mangle]
pub extern "C" fn vec_u8_len(ptr: *const RustVecU8) -> c_ulong {
    if ptr.is_null() {
        return 0;
    }
    unsafe { as_vec_ref(ptr).len() as c_ulong }
}

/// 获取容量
#[no_mangle]
pub extern "C" fn vec_u8_capacity(ptr: *const RustVecU8) -> c_ulong {
    if ptr.is_null() {
        return 0;
    }
    unsafe { as_vec_ref(ptr).capacity() as c_ulong }
}

/// 末尾 push 一个字节
#[no_mangle]
pub extern "C" fn vec_u8_push(ptr: *mut RustVecU8, value: c_uchar) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        as_vec_mut(ptr).push(value);
    }
}

/// 一次性 push 一段 bytes
#[no_mangle]
pub extern "C" fn vec_u8_push_bytes(ptr: *mut RustVecU8, data: *const c_uchar, len: c_ulong) {
    if ptr.is_null() || data.is_null() {
        return;
    }

    unsafe {
        let v = as_vec_mut(ptr);
        let slice = core::slice::from_raw_parts(data, len as usize);
        v.extend_from_slice(slice);
    }
}

/// 安全按下标读一个字节，成功返回 1，失败(越界/空指针)返回 0
#[no_mangle]
pub extern "C" fn vec_u8_get(ptr: *const RustVecU8, index: c_ulong, out: *mut c_uchar) -> i32 {
    if ptr.is_null() || out.is_null() {
        return 0;
    }
    unsafe {
        let v = as_vec_ref(ptr);
        let i = index as usize;
        if i >= v.len() {
            return 0;
        }
        *out = v[i];
    }
    1
}

/// 获取底层数据指针（可读写）
/// 注意：拿到这个指针之后，如果再 push/扩容，指针会失效。
#[no_mangle]
pub extern "C" fn vec_u8_data_mut(ptr: *mut RustVecU8) -> *mut c_uchar {
    if ptr.is_null() {
        return core::ptr::null_mut();
    }
    unsafe { as_vec_mut(ptr).as_mut_ptr() }
}
