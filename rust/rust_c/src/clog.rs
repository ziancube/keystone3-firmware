use cstr_core::CString;
#[cfg(feature = "sample_log")]
pub fn log_message(msg: &str) {
    unsafe {
        crate::bindings::log_simple_message(
            CString::new("Rust").unwrap().into_raw(),
            CString::new(msg).unwrap().into_raw(),
        );
    }
}

#[cfg(not(feature = "sample_log"))]
pub fn log_message(msg: &str) {
}
