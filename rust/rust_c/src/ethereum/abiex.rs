use crate::common::{types::{Ptr, PtrBytes}};
use crate::common::ffi::CSliceFFI;
use crate::common::utils::recover_c_array;
use crate::clog::log_message;

use alloc::format;

use app_ethereum::abiex;

#[no_mangle]
pub extern "C" fn eth_abiex_parse(
    chain_id: u64,
    address: Ptr<CSliceFFI<u8>>,
    data: Ptr<CSliceFFI<u8>>,
) {
    let address = unsafe { recover_c_array(address) };
    let data = unsafe { recover_c_array(data) };
    let address: [u8; 20] = address[..20].try_into().unwrap();

    let call = match abiex::contract_call_parse(chain_id, &address, &data) {
        Ok(call) => call,
        Err(e) => {
            log_message(&format!("contract_call_parse error: {:?}", e));
            return;
        }
    };
    let s = serde_json::to_string(&call).unwrap();
    log_message(&s);
}
