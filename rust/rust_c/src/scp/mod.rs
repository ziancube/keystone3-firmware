use crate::common::types::{PtrBytes, PtrVoid};

pub mod errors;
pub(crate) mod apdu;
pub mod scp03;
pub mod scp11;


pub type ScpContext = PtrVoid;

#[no_mangle]
pub extern "C" fn scp_context_create() -> ScpContext {
    panic!("not impl")
}

#[no_mangle]
pub extern  "C" fn scp_context_free(ctx: ScpContext) {
    if ctx.is_null() {
        return;
    }

    // unsafe {
    //     Box::from_raw(ctx as *mut Scp11c);
    // }
}

#[no_mangle]
pub extern  "C" fn scp_initialize(ctx: ScpContext) {
    panic!("not impl")
}

#[no_mangle]
pub extern  "C" fn scp_build_mutual_auth_data(ctx: ScpContext) -> PtrBytes {
    panic!("not impl")
}