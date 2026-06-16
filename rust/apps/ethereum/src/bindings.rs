extern "C" {
    pub fn get_token_info(chain_id: u64, address: *const u8, symbol: *mut cty::c_char, decimals: *mut u32);
}
