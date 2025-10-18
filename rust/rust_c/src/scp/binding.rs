use crate::scp::apdu::APDUResponse;

use super::errors::{Result, ScpError};
use super::apdu::APDU;

extern "C" {
    fn p256_load_sig_from_der(der: *const u8, der_len: usize, sig: *mut u8) -> i32;
    fn p256_verify_signature(pk: *const u8, digest: *const u8, sig: *const u8) -> i32;
    fn p256_gen_keypair(sk: *mut u8, pk: *mut u8) -> i32;
    fn p256_ecdh(sk: *const u8, pk: *const u8, key: *mut u8) -> i32;
    fn nfc_transmit_apdu(apdu: *const u8, apdu_len: usize, resp: *mut u8, resp_len: *mut usize) -> i32;
}

pub fn load_sig_from_der(der: &[u8]) -> Result<[u8; 64]> {
    let mut sig = [0u8; 64];
    let ret = unsafe { p256_load_sig_from_der(der.as_ptr(), der.len(), sig.as_mut_ptr()) };
    if ret != 0 {
        return Err(ScpError::FunctionFailed("p256_load_sig_from_der".into(),ret));
    }

    Ok(sig)
}

pub fn verify_signature(pk: &[u8], digest: &[u8], sig: &[u8]) -> Result<()> {
    let ret = unsafe {
        p256_verify_signature(pk.as_ptr(), digest.as_ptr(), sig.as_ptr())
    };
    if ret != 0 {
        return Err(ScpError::InvalidSignature);
    }
    Ok(())
}

pub fn gen_keypair() -> Result<([u8;32], [u8; 65])> {
    let mut sk = [0u8; 32];
    let mut pk = [0u8; 65];

    let ret = unsafe {
        p256_gen_keypair(sk.as_mut_ptr(), pk.as_mut_ptr())
    };

    if ret != 0 {
        return Err(ScpError::FunctionFailed("p256_gen_keypair".into(), ret));
    }

    Ok((sk, pk))
}

pub fn ecdh(sk: &[u8], pk: &[u8]) -> Result<[u8; 32]> {
    #[cfg(test)]
    {
        let mut key = [0u8; 32];
        let ret = unsafe {
            p256_ecdh(sk.as_ptr(), pk.as_ptr(), key.as_mut_ptr())
        };
        if ret != 0 {
            return Err(ScpError::FunctionFailed("p256_ecdh".into(), ret));
        }
        Ok(key)
    }

    #[cfg(not(test))]
    {
        let mut key = [0u8; 65];
        let ret = unsafe {
            p256_ecdh(sk.as_ptr(), pk.as_ptr(), key.as_mut_ptr())
        };
        if ret != 0 {
            return Err(ScpError::FunctionFailed("p256_ecdh".into(), ret));
        }
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&key[1..33]);
        Ok(shared)
    }
}

pub fn transmit_apdu(apdu: APDU) -> Result<APDUResponse> {
    let apdu = apdu.to_vec();
    let mut resp = [0u8; 270];
    let mut le = resp.len();
    let ret = unsafe {
        nfc_transmit_apdu(apdu.as_ptr(), apdu.len(), resp.as_mut_ptr(), &mut le as *mut usize)
    };

    if ret != 0 {
        return Err(ScpError::FunctionFailed("nfc_transmit_apdu".into(), ret));
    }

    if le == 0 {
        return Err(ScpError::InvalidLength);
    }
    Ok(APDUResponse::try_from(resp[..le].to_vec())?)
}