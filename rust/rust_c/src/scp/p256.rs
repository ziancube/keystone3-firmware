use thiserror::Error;

extern "C" {
    fn p256_load_sig_from_der(der: *const u8, der_len: usize, sig: *mut u8) -> i32;
    fn p256_verify_signature(pk: *const u8, digest: *const u8, sig: *const u8) -> i32;
    fn p256_gen_keypair(sk: *mut u8, pk: *mut u8) -> i32;
    fn p256_ecdh(sk: *const u8, pk: *const u8, key: *mut u8) -> i32;
}

#[derive(Error, Debug)]
pub enum P256Error {
    #[error("internal error")]
    InternalError,
    #[error("invalid data")]
    InvalidData,
    #[error("invalid signature")]
    InvalidSignature,
}

type Result<T> = ::core::result::Result<T, P256Error>;

pub fn load_sig_from_der(der: &[u8]) -> Result<[u8; 64]> {
    let mut sig = [0u8; 64];
    let ret = unsafe { p256_load_sig_from_der(der.as_ptr(), der.len(), sig.as_mut_ptr()) };
    if ret != 0 {
        return Err(P256Error::InvalidData);
    }

    Ok(sig)
}

pub fn verify_signature(pk: &[u8], digest: &[u8], sig: &[u8]) -> Result<()> {
    let ret = unsafe {
        p256_verify_signature(pk.as_ptr(), digest.as_ptr(), sig.as_ptr())
    };
    if ret != 0 {
        return Err(P256Error::InvalidSignature);
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
        return Err(P256Error::InternalError);
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
            return Err(P256Error::InternalError);
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
            return Err(P256Error::InternalError);
        }
        let mut shared = [0u8; 32];
        shared.copy_from_slice(&key[1..33]);
        Ok(shared)
    }
}
