use core::ptr::null_mut;
use alloc::vec;
use alloc::vec::Vec;
use alloc::boxed::Box;

use bytes::Bytes;

use crate::common::free::SimpleFree;
use crate::common::types::PtrString;
use crate::common::utils::recover_c_char;
use crate::scp::apdu::{APDUResponse, APDU};
use crate::scp::binding::{self, transmit_apdu};
use crate::scp::scp11::decode;
use crate::{apdu, extract_array, extract_ptr_with_type};
use crate::{
    common::{
        ffi::{CSliceFFI, VecFFI},
        free::Free,
        structs::{Response, SimpleResponse},
        types::PtrVoid,
    },
    scp::{
        errors::ScpError,
        scp11::{Scp11, Tagged},
    },
};

use super::errors::*;
use crate::clog::log_message;

type ScpContext = PtrVoid;

impl<'a> From<CSliceFFI<u8>> for &'a [u8] {
    fn from(value: CSliceFFI<u8>) -> Self {
        extract_array!(value.data, u8, value.size)
    }
}

// 我们使用 VecFFI 传递给c层，
// 同时使用 Response<VecFFI<T>> 返回error信息，但是 Response 需要 T 实现`Free`trait
// 实现一个空的, ScpContext 销毁使用 destory 函数
impl Free for ScpContext {
    fn free(&self) {}
}

impl Free for u8 {
    fn free(&self) {}
}
impl SimpleFree for u8 {
    fn free(&self) {}
}

#[no_mangle]
pub extern "C" fn free_Response_VecFFI_u8(resp: Response<VecFFI<u8>>) {
    SimpleFree::free(&resp);
}

#[no_mangle]
pub extern "C" fn nfc_select() {
    log_message("enter nfc select");
    let aid = vec![0x54, 0x50, 0x2d, 0x62, 0x61, 0x63, 0x6b, 0x75, 0x70, 0x01];
    let apdu = apdu!(0x00, 0xa4, 0x04, 0x00, data: aid);
    _ = transmit_apdu(apdu);
}
#[no_mangle]
pub extern "C" fn nfc_create_scp_context(
    aid: CSliceFFI<u8>,
    sk_oce: CSliceFFI<u8>,
    cert_oce: CSliceFFI<u8>,
    pk_ca_klcc: CSliceFFI<u8>,
) -> Response<ScpContext> {
    log_message("enter nfc_create_scp_context");
    if sk_oce.size != 32 {
        return Response::from(ScpError::InvalidParam);
    }

    if cert_oce.size == 0 {
        return Response::from(ScpError::InvalidParam);
    }

    if pk_ca_klcc.size != 65 {
        return Response::from(ScpError::InvalidParam);
    }

    if aid.size == 0 {
        return Response::from(ScpError::InvalidParam);
    }

    let aid: &[u8] = aid.into();

    // step 0. select applet
    if let Err(e) = select(aid.to_vec()) {
        return e.into();
    }

    // step 1. get CERT.SD
    let cert_sd = match get_sd_cert() {
        Ok(cert) => cert,
        Err(e) => return e.into(),
    };

    let sk_oce: &[u8] = sk_oce.into();
    let sk_oce: [u8; 32] = sk_oce.try_into().unwrap();
    let scp11 = match Scp11::with_certs(sk_oce, cert_oce.into(), pk_ca_klcc.into(), &cert_sd) {
        Ok(scp11) => scp11,
        Err(e) => return e.into(),
    };

    let ctx = Box::new(scp11);
    Response::success(Box::into_raw(ctx) as ScpContext)
}

#[no_mangle]
pub extern "C" fn nfc_destory_scp_context(ctx: ScpContext) {
    if ctx.is_null() {
        return;
    }

    let _x = unsafe { Box::from_raw(ctx as *mut Scp11) };
}

#[no_mangle]
pub extern "C" fn nfc_open_secure_channel(ctx: ScpContext, host_id: PtrString) -> SimpleResponse<u8> {
    if ctx.is_null() || host_id.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }

    let scp11 = extract_ptr_with_type!(ctx, Scp11);

    // step 0. perform secure operation
    if let Err(e) = perform_secure_operation(scp11) {
        return e.into();
    }

    // step 1. mutual authenticate
    let host_id = recover_c_char(host_id);
    let data = match mutual_authenticate(scp11, &host_id) {
        Ok(data) => data,
        Err(e) => return e.into(),
    };

    // step 2. open secure channel
    match scp11.open_secure_channel(&data) {
        Ok(_) => SimpleResponse::success(null_mut()),
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn nfc_reset_wallet(ctx: ScpContext) -> SimpleResponse<u8> {
    if ctx.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }
    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: vec![0xdf, 0xfe, 0x02, 0x82, 0x05]);
    let resp = match transmit_safe_apdu(scp11, apdu) {
        Ok(resp) => resp,
        Err(e) => return e.into(),
    };
    match resp.check_sw() {
        Ok(_) => SimpleResponse::success(null_mut()),
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn nfc_is_pin_set(ctx: ScpContext, exist: *mut u32) -> SimpleResponse<u8> {
    if ctx.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }
    if exist.is_null() {
        return SimpleResponse::from(ScpError::InvalidParam);
    }
    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data:vec![ 0xDF,0xFF, 0x02, 0x81, 0x05 ]);

    let resp = match transmit_safe_apdu(scp11, apdu) {
        Ok(resp) => resp,
        Err(e) => return e.into(),
    };
    match resp.check_sw() {
        Ok(_) => {
            unsafe {
                *exist = if resp[0] == 0x02 { 0 } else { 1 };
            }
            SimpleResponse::success(null_mut())
        }
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn nfc_reset_pin(ctx: ScpContext, pin: PtrString) -> SimpleResponse<u8> {
    if ctx.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }
    if pin.is_null() {
        return SimpleResponse::from(ScpError::InvalidParam);
    }
    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let pin = recover_c_char(pin);
    let n = pin.len();

    // DFFE X 8204 X 00 L V
    let mut data: Vec<u8> = Vec::with_capacity(n + 8);

    let n = n as u8;
    data.extend(&[0xDF, 0xFE, n + 5, 0x82, 0x04, n + 2, 0x00, n]);
    data.extend(pin.as_bytes());

    let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: data);

    let resp = match transmit_safe_apdu(scp11, apdu) {
        Ok(resp) => resp,
        Err(e) => return e.into(),
    };
    match resp.check_sw() {
        Ok(_) => SimpleResponse::success(null_mut()),
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn nfc_get_pin_retry_times(ctx: ScpContext, count: *mut u32) -> SimpleResponse<u8> {
    if ctx.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }
    if count.is_null() {
        return SimpleResponse::from(ScpError::InvalidParam);
    }
    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let data = vec![0xdf, 0xff, 0x02, 0x81, 0x02];
    let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: data);
    let resp = match transmit_safe_apdu(scp11, apdu) {
        Ok(resp) => resp,
        Err(e) => return e.into(),
    };
    match resp.check_sw() {
        Err(e) => return e.into(),
        _ => {}
    };

    match resp.data() {
        Some(data) => {
            unsafe {
                *count = data[0] as u32;
            }
            SimpleResponse::success(null_mut())
        }
        None => SimpleResponse::from(ScpError::UnexpectedContent),
    }
}

#[no_mangle]
pub extern "C" fn nfc_verify_pin(
    ctx: ScpContext,
    pin: PtrString,
    count: *mut u32,
) -> SimpleResponse<u8> {
    if ctx.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }
    if pin.is_null() {
        return SimpleResponse::from(ScpError::InvalidParam);
    }
    if count.is_null() {
        return SimpleResponse::from(ScpError::InvalidParam);
    }
    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let pin = recover_c_char(pin);
    let n = pin.len();
    let mut data: Vec<u8> = Vec::with_capacity(n + 1);
    data.push(n as u8);
    data.extend(pin.as_bytes());

    let apdu = apdu!(0x80, 0x20, 0x00, 0x00, data: data);
    let resp = match transmit_safe_apdu(scp11, apdu) {
        Ok(resp) => resp,
        Err(e) => return e.into(),
    };

    let sw = resp.sw();
    match sw {
        0x9000 => SimpleResponse::success(null_mut()),
        // locked
        0x6983 => {
            unsafe {
                *count = 0;
            }
            SimpleResponse::from(ScpError::InvalidPin)
        }
        0x63c0..0x63cf => {
            unsafe {
                *count = (sw & 0x0f) as u32;
            }
            SimpleResponse::from(ScpError::InvalidPin)
        }
        _ => SimpleResponse::from(ScpError::APDUResponseFailed(sw)),
    }
}

#[no_mangle]
pub extern "C" fn nfc_change_pin(
    ctx: ScpContext,
    old_pin: PtrString,
    new_pin: PtrString,
    count: *mut u32,
) -> SimpleResponse<u8> {
    if ctx.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }
    if old_pin.is_null() || new_pin.is_null() {
        return SimpleResponse::from(ScpError::InvalidParam);
    }
    if count.is_null() {
        return SimpleResponse::from(ScpError::InvalidParam);
    }

    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let old_pin = recover_c_char(old_pin);
    let new_pin = recover_c_char(new_pin);

    let on = old_pin.len();
    let nn = new_pin.len();

    // DFFE X 8204 X LV LV
    let mut data: Vec<u8> = Vec::with_capacity(on + nn + 8);
    let on = on as u8;
    let nn = nn as u8;
    data.extend(&[0xDF, 0xFE, on + nn + 5, 0x82, 0x04, on + nn + 2]);
    data.push(on);
    data.extend(old_pin.as_bytes());
    data.push(nn);
    data.extend(new_pin.as_bytes());

    let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: data);
    let resp = match transmit_safe_apdu(scp11, apdu) {
        Ok(resp) => resp,
        Err(e) => return e.into(),
    };

    let sw = resp.sw();
    match sw {
        0x9000 => SimpleResponse::success(null_mut()),
        // locked
        0x6983 => {
            unsafe {
                *count = 0;
            }
            SimpleResponse::from(ScpError::InvalidPin)
        }
        0x63c0..0x63cf => {
            unsafe {
                *count = (sw & 0x0f) as u32;
            }
            SimpleResponse::from(ScpError::InvalidPin)
        }
        _ => SimpleResponse::from(ScpError::APDUResponseFailed(sw)),
    }
}

#[no_mangle]
pub extern "C" fn nfc_write_data(ctx: ScpContext, slot: u8, data: CSliceFFI<u8>) -> SimpleResponse<u8> {
    if ctx.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }

    if data.size == 0 || slot >= 40 {
        return SimpleResponse::from(ScpError::InvalidParam);
    }

    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let data: &[u8] = data.into();

    let apdu = apdu!(0x80, 0x3b, 0x00, slot, data: data.to_vec());
    let resp = match transmit_safe_apdu(scp11, apdu) {
        Ok(resp) => resp,
        Err(e) => return e.into(),
    };
    match resp.check_sw() {
        Ok(_) => SimpleResponse::success(null_mut()),
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn nfc_read_data(ctx: ScpContext, slot: u8) -> Response<VecFFI<u8>> {
    if ctx.is_null() {
        return Response::from(ScpError::InvalidSession);
    }

    if slot >= 40 {
        return Response::from(ScpError::InvalidParam);
    }
    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let apdu = apdu!(0x80, 0x4b, 0x00, slot);
    let resp = match transmit_safe_apdu(scp11, apdu) {
        Ok(resp) => resp,
        Err(e) => return e.into(),
    };
    match resp.check_sw() {
        Err(e) => return e.into(),
        _ => {}
    };

    match resp.data() {
        Some(data) => {
            let data = data.to_vec();
            let data = data.into();
            Response::success(data)
        }
        None => Response::from(ScpError::UnexpectedContent),
    }
}

#[no_mangle]
pub extern "C" fn nfc_delete_data(ctx: ScpContext, slot: u8) -> SimpleResponse<u8> {
    if ctx.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }

    if slot >= 40 {
        return SimpleResponse::from(ScpError::InvalidParam);
    }
    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let apdu = apdu!(0x80, 0x7a, 0x00, slot);
    let resp = match transmit_safe_apdu(scp11, apdu) {
        Ok(resp) => resp,
        Err(e) => return e.into(),
    };
    match resp.check_sw() {
        Ok(_) => SimpleResponse::success(null_mut()),
        Err(e) => e.into(),
    }
}

#[no_mangle]
pub extern "C" fn nfc_is_stored_in_slot(ctx: ScpContext, slot: u8, stored: *mut u32) -> SimpleResponse<u8> {
    if ctx.is_null() {
        return SimpleResponse::from(ScpError::InvalidSession);
    }

    if slot >= 40 {
        return SimpleResponse::from(ScpError::InvalidParam);
    }
    if stored.is_null() {
        return SimpleResponse::from(ScpError::InvalidParam);
    }

    let scp11 = extract_ptr_with_type!(ctx, Scp11);
    let bitmap = match get_store_bitmap(scp11) {
        Err(e) => return e.into(),
        Ok(bitmap) => bitmap,
    };

    unsafe {
        if (bitmap & (1 << slot)) != 0 {
            *stored = 1;
        } else {
            *stored = 0;
        }
    };
    SimpleResponse::success(null_mut())
}

fn transmit_safe_apdu(scp11: &Scp11, apdu: APDU) -> Result<APDUResponse> {
    let apdu = scp11.encrypt_apdu(apdu).expect("encrypt apdu");
    let resp = transmit_apdu(apdu)?;
    let resp = scp11.decrypt_apdu_response(&resp)?;
    Ok(resp)
}

fn select(aid: Vec<u8>) -> Result<()> {
    let apdu = apdu!(0x00, 0xa4, 0x04, 0x00, data: aid);
    let resp = binding::transmit_apdu(apdu)?;
    resp.check_sw()?;
    Ok(())
}

fn get_sd_cert() -> Result<Vec<u8>> {
    let apdu = apdu!( 0x80, 0xCA, 0xBF, 0x21, data: vec![0xA6, 0x04, 0x83, 0x02, 0x15, 0x18]);
    let resp = binding::transmit_apdu(apdu)?;
    resp.check_sw()?;

    // cert store: BF21xxxx
    let store = match resp.data() {
        Some(data) => data.to_vec(),
        None => return Err(ScpError::UnexpectedContent),
    };

    let mut buf = Bytes::from(store);
    let cert_store: Tagged<0xBF21, Vec<u8>> = decode(&mut buf)?;
    Ok(cert_store.value)
}

fn perform_secure_operation(scp11: &Scp11) -> Result<()> {
    let apdu = scp11.perform_secure_operation();
    let resp = transmit_apdu(apdu)?;
    resp.check_sw()?;
    Ok(())
}

fn mutual_authenticate(scp11: &mut Scp11, host_id: &str) -> Result<Vec<u8>> {
    let apdu = scp11.mutual_authenticate(host_id);
    let resp = transmit_apdu(apdu)?;
    resp.check_sw()?;
    resp.data()
        .map(|d| d.to_vec())
        .ok_or(ScpError::UnexpectedContent)
}

fn get_store_bitmap(scp11: &Scp11) -> Result<u64> {
    let apdu = apdu!(0x80, 0x6a, 0x00, 0x00);
    let resp = transmit_safe_apdu(scp11, apdu)?;
    let data = resp.data().ok_or(ScpError::UnexpectedContent)?;
    let mut data = data.to_vec();
    data.reverse();
    let mut bitmap: u64 = 0;
    for d in data {
        bitmap <<= 8;
        bitmap += d as u64;
    }
    Ok(bitmap)
}
