use crate::common::types::{PtrBytes, PtrString, PtrT};
use crate::common::ur::{UREncodeResult, FRAGMENT_MAX_LENGTH_DEFAULT};
use crate::common::utils::recover_c_char;
use alloc::slice;
use ur_registry::keypal::keypal_device_info::KeypalDeviceInfo;
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
