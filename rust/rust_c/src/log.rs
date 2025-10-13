use cstr_core::CString;
pub fn log_message(msg: &str) {
    unsafe {
        crate::bindings::log_simple_message(
            CString::new("Rust").unwrap().into_raw(),
            CString::new(msg).unwrap().into_raw(),
        );
    }
}
