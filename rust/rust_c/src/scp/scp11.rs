use core::cell::{Cell, RefCell};

use crate::alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use alloc::string::String;
use cryptoxide::hashing::{sha1, sha2, sha256};

use log::debug;

use crate::apdu;
use crate::scp::apdu::APDUResponse;

use super::apdu::APDU;
use super::binding;
use super::scp03::Scp03;
use super::errors::*;

use aes;
use bytes::{Buf, BufMut, Bytes, BytesMut, TryGetError};
use cmac::{Cmac, Mac as CMac};
use thiserror;
use thiserror::Error;

type AesCmac = Cmac<aes::Aes128>;

impl From<TryGetError> for ScpError {
    fn from(_: TryGetError) -> Self {
        ScpError::LengthNotEnough
    }
}


pub trait Decode: Sized {
    fn decode(buf: &mut Bytes) -> Result<Self>;
}
pub trait Encode: Sized {
    fn encode(&self, buf: &mut BytesMut);
}

pub fn decode<T>(buf: &mut Bytes) -> Result<T>
where
    T: Decode,
{
    T::decode(buf)
}

pub fn encode<T>(obj: &T) -> Bytes
where
    T: Encode,
{
    let mut buf = BytesMut::new();
    obj.encode(&mut buf);
    buf.freeze()
}

pub fn try_decode<const TAG: u16, T>(buf: &mut Bytes) -> Result<Option<Tagged<TAG, T>>>
where
    Tagged<TAG, T>: Decode,
{
    // 不要消耗
    let tag = match TAG {
        0..=0xff => buf[0] as u16,
        _ => {
            if buf.remaining() < 2 {
                return Err(ScpError::LengthNotEnough);
            }
            u16::from_be_bytes(buf[0..2].try_into().unwrap())
        }
    };
    if tag != TAG {
        return Ok(None);
    }
    let v = decode(buf)?;
    Ok(Some(v))
}

pub struct Tagged<const TAG: u16, T> {
    pub value: T,
}

fn decode_length(buf: &mut Bytes) -> Result<usize> {
    let n = buf.try_get_u8()? as usize;
    match n {
        0..=127 => Ok(n as usize),
        _ => {
            let size = (n & 0x7f) as usize;
            if buf.remaining() < size {
                return Err(ScpError::LengthNotEnough);
            }
            let bytes = buf.split_to(size);
            let n = bytes
                .into_iter()
                .take(size)
                .fold(0usize, |acc, e| acc * 256 + e as usize);
            Ok(n)
        }
    }
}
fn encode_length(length: usize, buf: &mut BytesMut) {
    match length {
        0..=127 => buf.put_u8(length as u8),
        _ => {
            let mut bytes = Vec::with_capacity(4);
            bytes.extend(length.to_be_bytes().into_iter().skip_while(|x| *x == 0));
            let l = bytes.len() as u8;
            buf.put_u8(0x80 | (l));
            buf.put(bytes.as_slice());
        }
    }
}

fn encode_tag(tag: u16, buf: &mut BytesMut) {
    match tag {
        0..=0xff => buf.put_u8(tag as u8),
        _ => buf.put_u16(tag),
    }
}
fn verify_tag(tag: u16, buf: &mut Bytes) -> Result<()> {
    let _tag = if tag <= 0xFF {
        buf.try_get_u8()? as u16
    } else {
        buf.try_get_u16()?
    };
    if tag != _tag {
        return Err(ScpError::TagNotMatch {
            want: tag,
            get: _tag,
        });
    }

    Ok(())
}

impl<const TAG: u16, T> From<T> for Tagged<TAG, T> {
    fn from(value: T) -> Self {
        Self { value: value }
    }
}

impl<const TAG: u16, T> Tagged<TAG, T> {
    fn encode_length(length: usize, buf: &mut BytesMut) {
        encode_length(length, buf);
    }
    fn decode_length(buf: &mut Bytes) -> Result<usize> {
        decode_length(buf)
    }
    fn encode_tag(buf: &mut BytesMut) {
        encode_tag(TAG, buf);
    }
    fn verify_tag(buf: &mut Bytes) -> Result<()> {
        verify_tag(TAG, buf)
    }
}

/// u8
impl<const TAG: u16> Encode for Tagged<TAG, u8> {
    fn encode(&self, buf: &mut BytesMut) {
        Self::encode_tag(buf);
        Self::encode_length(1, buf);
        buf.put_u8(self.value);
    }
}

/// &[u8]
impl<const TAG: u16> Encode for Tagged<TAG, &[u8]> {
    fn encode(&self, buf: &mut BytesMut) {
        Self::encode_tag(buf);
        Self::encode_length(self.value.len(), buf);
        buf.put_slice(self.value);
    }
}

/// [u8;N]
impl<const TAG: u16, const N: usize> Encode for Tagged<TAG, [u8; N]> {
    fn encode(&self, buf: &mut BytesMut) {
        Self::encode_tag(buf);
        Self::encode_length(N, buf);
        buf.put_slice(&self.value);
    }
}

impl<const TAG: u16, const N: usize> Decode for Tagged<TAG, [u8; N]> {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size != N {
            return Err(ScpError::InvalidLength);
        }
        let mut v = [0u8; N];
        buf.split_to(N).copy_to_slice(&mut v);
        Ok(Self { value: v })
    }
}

/// ()
impl<const TAG: u16> Decode for Tagged<TAG, ()> {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size != 0 {
            return Err(ScpError::UnexpectedContent);
        }
        Ok(Tagged { value: () })
    }
}
impl<const TAG: u16> Encode for Tagged<TAG, ()> {
    fn encode(&self, buf: &mut BytesMut) {
        Self::encode_tag(buf);
        Self::encode_length(0, buf);
    }
}

/// String
impl From<core::str::Utf8Error> for ScpError {
    fn from(value: core::str::Utf8Error) -> Self {
        ScpError::InvalidString(value.to_string())
    }
}

impl<const TAG: u16> Decode for Tagged<TAG, String> {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if buf.remaining() < size {
            return Err(ScpError::LengthNotEnough);
        }
        let bytes = buf.split_to(size);
        let value = str::from_utf8(&bytes)?.to_string();
        Ok(Tagged { value: value })
    }
}

impl<const TAG: u16> Encode for Tagged<TAG, String> {
    fn encode(&self, buf: &mut BytesMut) {
        let size = self.value.len();
        Self::encode_tag(buf);
        Self::encode_length(size, buf);
        buf.put(self.value.as_bytes());
    }
}

/// KeyUsage
// GPCS 11.1.9 && GPC-F-SCP11 6.4.2.4
pub enum KeyUsage {
    SignatureVerification,
    Agreement,
}
impl<const TAG: u16> Decode for Tagged<TAG, KeyUsage> {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        match size {
            1 => {
                let ku = buf.try_get_u8()?;
                if ku != 0x82 {
                    return Err(ScpError::UnexpectedContent);
                }
                Ok(Self {
                    value: KeyUsage::SignatureVerification,
                })
            }
            2 => {
                let ku = buf.try_get_u16()?;
                if ku != 0x0080 {
                    return Err(ScpError::UnexpectedContent);
                }
                Ok(Self {
                    value: KeyUsage::Agreement,
                })
            }
            _ => Err(ScpError::InvalidLength),
        }
    }
}
impl<const TAG: u16> Encode for Tagged<TAG, KeyUsage> {
    fn encode(&self, buf: &mut BytesMut) {
        Self::encode_tag(buf);
        match self.value {
            KeyUsage::SignatureVerification => {
                Self::encode_length(1, buf);
                buf.put_u8(0x82);
            }
            KeyUsage::Agreement => {
                Self::encode_length(2, buf);
                buf.put_slice(&[00, 0x80]);
            }
        }
    }
}

/// Date
pub struct Date {
    pub year: u16,
    pub month: u8,
    pub day: u8,
}

impl<const TAG: u16> Decode for Tagged<TAG, Date> {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        // `BCD` format `YYYYMMDD`
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size != 4 {
            return Err(ScpError::LengthNotEnough);
        }
        let mut year = 0u16;
        for _ in 0..2 {
            year = year * 256 + buf.try_get_u8()? as u16;
        }

        let month = buf.try_get_u8()?;

        let day = buf.try_get_u8()?;

        Ok(Self {
            value: Date {
                year: year,
                month: month,
                day: day,
            },
        })
    }
}

impl<const TAG: u16> Encode for Tagged<TAG, Date> {
    fn encode(&self, buf: &mut BytesMut) {
        // `BCD` format `YYYYMMDD`
        Self::encode_tag(buf);
        Self::encode_length(4, buf);

        let y = (self.value.year >> 8) as u8;
        buf.put_u8(y);

        let y = (self.value.year & 0xFF) as u8;
        buf.put_u8(y);

        let m = self.value.month;
        buf.put_u8(m);

        let d = self.value.day;
        buf.put_u8(d);
    }
}

#[derive(Clone, Copy)]
pub enum KeyParamterReference {
    P256 = 0,
    P384 = 1,
    P512 = 2,
    BrainpoolP256r1 = 3,
    BrainpoolP256t1 = 4,
    BrainpoolP384r1 = 5,
    BrainpoolP384t1 = 6,
    BrainpoolP512r1 = 7,
    BrainpoolP512t1 = 8,
    SM2 = 9,
}

impl<const TAG: u16> Decode for Tagged<TAG, KeyParamterReference> {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size != 1 {
            return Err(ScpError::UnexpectedContent);
        }
        let v = buf.try_get_u8()?;
        if v > KeyParamterReference::SM2 as u8 {
            return Err(ScpError::UnexpectedContent);
        }
        let kpr = unsafe { ::core::mem::transmute(v) };
        Ok(Self { value: kpr })
    }
}
impl<const TAG: u16> Encode for Tagged<TAG, KeyParamterReference> {
    fn encode(&self, buf: &mut BytesMut) {
        Self::encode_tag(buf);
        Self::encode_length(1, buf);
        buf.put_u8(self.value as u8);
    }
}

/// Vec<u8>
impl<const TAG: u16> Decode for Tagged<TAG, Vec<u8>> {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size > buf.remaining() {
            return Err(ScpError::LengthNotEnough);
        }

        let v = buf.split_to(size);
        Ok(Self { value: v.to_vec() })
    }
}

impl<const TAG: u16> Encode for Tagged<TAG, Vec<u8>> {
    fn encode(&self, buf: &mut BytesMut) {
        Self::encode_tag(buf);
        let size = self.value.len();
        Self::encode_length(size, buf);
        buf.put_slice(&self.value);
    }
}

/// Bytes
impl<const TAG: u16> Decode for Tagged<TAG, Bytes> {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size > buf.remaining() {
            return Err(ScpError::LengthNotEnough);
        }

        let v = buf.split_to(size);
        Ok(Self { value: v })
    }
}

impl<const TAG: u16> Encode for Tagged<TAG, Bytes> {
    fn encode(&self, buf: &mut BytesMut) {
        Self::encode_tag(buf);
        let size = self.value.len();
        Self::encode_length(size, buf);
        buf.put_slice(&self.value);
    }
}

/// PublicKeyData
pub struct PublicKeyData {
    pub q: Tagged<0xB0, Vec<u8>>,
    pub kpr: Tagged<0xF0, KeyParamterReference>,
}

impl<const TAG: u16> Decode for Tagged<TAG, PublicKeyData> {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        Self::verify_tag(buf)?;
        _ = Self::decode_length(buf)?;
        let q = decode(buf)?;
        let kpr = decode(buf)?;
        Ok(Self {
            value: PublicKeyData { q: q, kpr: kpr },
        })
    }
}

impl<const TAG: u16> Encode for Tagged<TAG, PublicKeyData> {
    fn encode(&self, buf: &mut BytesMut) {
        let mut bytes = BytesMut::new();
        self.value.q.encode(&mut bytes);
        self.value.kpr.encode(&mut bytes);
        let size = bytes.len();
        Self::encode_tag(buf);
        Self::encode_length(size, buf);
        buf.put_slice(&bytes);
    }
}

pub struct Certificate {
    pub sn: Tagged<0x93, String>,
    pub ca_id: Tagged<0x42, String>,
    pub subject: Tagged<0x5F20, String>,
    pub key_usage: Tagged<0x95, KeyUsage>,
    pub effective: Tagged<0x5F25, Date>,
    pub expiration: Tagged<0x5F24, Date>,
    pub data: Tagged<0x53, ()>,
    pub restrictions: Option<Tagged<0xBF20, ()>>,
    pub pk: Tagged<0x7F49, PublicKeyData>,
    pub sig: Tagged<0x5F37, Vec<u8>>,
}

impl Certificate {
    pub fn unsigned_bytes(&self) -> Bytes {
        let mut buf = BytesMut::new();
        self.sn.encode(&mut buf);
        self.ca_id.encode(&mut buf);
        self.subject.encode(&mut buf);
        self.key_usage.encode(&mut buf);
        self.effective.encode(&mut buf);
        self.expiration.encode(&mut buf);
        self.data.encode(&mut buf);
        if let Some(r) = &self.restrictions {
            r.encode(&mut buf);
        }
        self.pk.encode(&mut buf);

        buf.into()
    }
}

impl Encode for Certificate {
    fn encode(&self, buf: &mut BytesMut) {
        encode_tag(0x7f21, buf);

        let bytes = {
            let mut buf = BytesMut::with_capacity(512);
            self.sn.encode(&mut buf);
            self.ca_id.encode(&mut buf);
            self.subject.encode(&mut buf);
            self.key_usage.encode(&mut buf);
            self.effective.encode(&mut buf);
            self.expiration.encode(&mut buf);
            self.data.encode(&mut buf);
            if let Some(o) = &self.restrictions {
                o.encode(&mut buf);
            }
            self.pk.encode(&mut buf);
            self.sig.encode(&mut buf);
            buf
        };

        encode_length(bytes.len(), buf);
        buf.put_slice(&bytes);
    }
}

impl Decode for Certificate {
    fn decode(buf: &mut Bytes) -> Result<Self> {
        verify_tag(0x7f21, buf)?;
        _ = decode_length(buf)?;
        let sn = decode(buf)?;
        let ca_id = decode(buf)?;
        let subject = decode(buf)?;
        let key_usage = decode(buf)?;
        let effective = decode(buf)?;
        let expiration = decode(buf)?;
        let data = decode(buf)?;
        let restrictions = try_decode(buf)?;
        let pk = decode(buf)?;
        let sig = decode(buf)?;

        Ok(Self {
            sn: sn,
            ca_id: ca_id,
            subject: subject,
            key_usage: key_usage,
            effective: effective,
            expiration: expiration,
            data: data,
            restrictions: restrictions,
            pk: pk,
            sig: sig,
        })
    }
}

// scp11 6.5.2.3
struct ControlReference {
    scp_id_param: Tagged<0x90, [u8; 2]>,
    key_usage: Tagged<0x95, u8>,
    key_type: Tagged<0x80, u8>,
    key_length: Tagged<0x81, u8>,
    host_id: Tagged<0x84, String>,
}

impl Encode for ControlReference {
    fn encode(&self, buf: &mut BytesMut) {
        encode_tag(0xA6, buf);

        let mut buf2 = BytesMut::with_capacity(128);
        self.scp_id_param.encode(&mut buf2);
        self.key_usage.encode(&mut buf2);
        self.key_type.encode(&mut buf2);
        self.key_length.encode(&mut buf2);
        self.host_id.encode(&mut buf2);

        encode_length(buf2.len(), buf);
        buf.put(buf2);
    }
}

pub struct Scp11 {
    sk_oce: [u8; 32],
    cert_oce: Certificate,

    // cert_ca_klcc: Certificate,
    cert_sd: Certificate,

    esk: Option<[u8; 32]>,
    epk: Option<[u8; 65]>,
    host_id: Option<String>,

    // cache `MUTUAL AUTHENTICATE` command data
    ma_data: Option<Vec<u8>>,

    // keys
    key_dek: Option<[u8; 16]>,
    s_enc_key: Option<[u8; 16]>,
    s_mac_key: Option<[u8; 16]>,
    s_rmac_key: Option<[u8; 16]>,
    s_dek_key: Option<[u8; 16]>,

    // scp03 client
    scp03: Option<Scp03>,
}

impl Scp11 {
    pub fn with_certs(
        sk_oce: [u8; 32],
        oce: &[u8],
        // ca_klcc: &[u8],
        pk_ca_klcc: &[u8],
        sd: &[u8],
    ) -> Result<Scp11> {
        let mut buf = Bytes::copy_from_slice(oce);
        let cert_oce = decode::<Certificate>(&mut buf)?;

        // let mut buf = Bytes::copy_from_slice(ca_klcc);
        // let cert_ca_klcc = decode::<Certificate>(&mut buf)?;

        let mut buf = Bytes::copy_from_slice(sd);
        let cert_sd = decode::<Certificate>(&mut buf)?;

        // use pk.ca.klcc verify sd

        // 太丑了
        // let pk = cert_ca_klcc.pk.value.q.value.as_slice();
        let sig = cert_sd.sig.value.as_slice();
        let unsigned = cert_sd.unsigned_bytes();
        let digest = sha256(&unsigned);

        // convert der to R||S
        let sig = binding::load_sig_from_der(sig)?;
        // p256::verify_signature(pk, &digest, &sig).map_err(|_| Scp11Error::InvalidCert)?;

        match binding::verify_signature(&pk_ca_klcc, &digest, &sig){
            Err(_) => return Err(ScpError::InvalidCertficate),
            Ok(_) => {},
        };

        Ok(Scp11 {
            sk_oce: sk_oce,
            cert_oce: cert_oce,
            // cert_ca_klcc: cert_ca_klcc,
            cert_sd: cert_sd,
            esk: None,
            epk: None,
            host_id: None,
            ma_data: None,
            key_dek: None,
            s_enc_key: None,
            s_mac_key: None,
            s_rmac_key: None,
            s_dek_key: None,
            scp03: None,
        })
    }

    pub fn perform_secure_operation(&self) -> APDU {
        let mut buf = BytesMut::with_capacity(256);
        self.cert_oce.encode(&mut buf);
        apdu!(0x80, 0x2A, 0x18, 0x10, data: buf.to_vec())
    }

    pub fn mutual_authenticate(&mut self, host_id: &str) -> APDU {
        let (sk, pk) = binding::gen_keypair().unwrap();

        let cr = ControlReference {
            scp_id_param: [0x11u8, 0x07u8].into(),
            key_usage: 0x3c.into(),
            key_type: 0x88.into(),
            key_length: 0x10.into(),
            host_id: host_id.to_string().into(),
        };

        let epk: Tagged<0x5f49, _> = pk.into();

        let mut buf = BytesMut::with_capacity(256);
        cr.encode(&mut buf);
        epk.encode(&mut buf);

        self.esk = Some(sk);
        self.epk = Some(pk);
        self.host_id = Some(host_id.to_string());
        self.ma_data = Some(buf.to_vec());

        apdu!(0x80, 0x82, 0x18, 0x15, data: buf.to_vec())
    }

    pub fn open_secure_channel(&mut self, data: &[u8]) -> Result<()> {
        // 6.5.3.1 MUTUAL AUTHENTICATE Response Data
        let mut buf = Bytes::copy_from_slice(data);

        let pk_sd = decode::<Tagged<0x5f49, Bytes>>(&mut buf)?;
        let receipt = decode::<Tagged<0x86, [u8; 16]>>(&mut buf)?;

        // complare pk.sd
        if pk_sd.value != self.cert_sd.pk.value.q.value {
            return Err(ScpError::InvalidCertficate);
        }

        self.derive_key()?;

        // verify receipt
        // scp11 6.5.2.3 Table 6-19
        let ma = self.ma_data.as_ref().unwrap();

        debug!("key_dek: {}", hex::encode(&self.key_dek.unwrap()));
        debug!("MA data: {}", hex::encode(ma));
        let receipt2: [u8; 16] = AesCmac::new(&self.key_dek.unwrap().into())
            .chain_update(ma)
            .chain_update(&encode(&pk_sd))
            .finalize()
            .into_bytes()
            .into();

        if receipt.value != receipt2 {
            return Err(ScpError::InvalidReceipt);
        }

        let client = Scp03 {
            s_enc: self.s_enc_key.as_ref().unwrap().clone(),
            s_mac: self.s_mac_key.as_ref().unwrap().clone(),
            s_rmac: self.s_rmac_key.as_ref().unwrap().clone(),
            counter: Cell::new(1),
            mac_chain: RefCell::new(receipt2),
        };
        self.scp03 = Some(client);
        Ok(())
    }

    pub fn encrypt_apdu(&self, apdu: APDU) -> Result<APDU> {
        match &self.scp03 {
            None => Err(ScpError::InvalidSession),
            Some(scp03) => {
                Ok(scp03.encrypt_apdu(apdu))
            }
        }
    }

    pub fn decrypt_apdu_response(&self, resp: &[u8]) -> Result<APDUResponse> {
        match &self.scp03 {
            None => Err(ScpError::InvalidSession),
            Some(scp03) => {
                scp03.decrypt_apdu_response(resp)
            }
        }

    }

    fn derive_key(&mut self) -> Result<()> {
        let host_id = self.host_id.as_ref().ok_or(ScpError::InvalidParam)?;

        let es = self.shses()?;
        let ss = self.shsss()?;
        let mut z = [0u8; 40];
        z[..20].copy_from_slice(&es);
        z[20..].copy_from_slice(&ss);
        debug!("Z: {}", hex::encode(&z));

        let mut shared_info = BytesMut::with_capacity(128);
        // key-usage, key-type, key-length
        shared_info.put([0x3cu8, 0x88, 0x10].as_slice());
        // hostid: LV
        shared_info.put_u8(host_id.len() as u8);
        shared_info.put(host_id.as_bytes());
        // card-group-id aka. subject
        shared_info.put(self.cert_sd.subject.value.as_bytes());
        debug!("shared: {}", hex::encode(&shared_info));
        let session_key: [u8; 80] = Self::kdf(&z, &shared_info.freeze());
        debug!("session: {}", hex::encode(&session_key));
        let mut keys: [[u8; 16]; 5] = Default::default();
        keys.iter_mut()
        .zip(session_key.chunks(16))
        .for_each(|(key, chunk)| {
            key.copy_from_slice(chunk);
        });
        self.key_dek = Some(keys[0]);
        self.s_enc_key = Some(keys[1]);
        self.s_mac_key = Some(keys[2]);
        self.s_rmac_key = Some(keys[3]);
        self.s_dek_key = Some(keys[4]);
        Ok(())
    }

    fn shsss(&self) -> Result<[u8; 20]> {
        let sd_pk = self.cert_sd.pk.value.q.value.as_ref();
        let key = binding::ecdh(&self.sk_oce, sd_pk)?;
        debug!("ss session key: {}", hex::encode(&key));
        let ss = sha1(&key);
        debug!("ss: {}", hex::encode(&ss));
        Ok(ss)
    }

    fn shses(&self) -> Result<[u8; 20]> {
        let sd_pk = self.cert_sd.pk.value.q.value.as_ref();
        let esk = self.esk.as_ref().ok_or(ScpError::InvalidParam)?;
        let key = binding::ecdh(esk, sd_pk)?;
        debug!("es session key: {}", hex::encode(&key));
        let es = sha1(&key);
        debug!("es: {}", hex::encode(&es));
        Ok(es)
    }

    fn  kdf<const N: usize>(z: &[u8], shared_info: &[u8]) -> [u8; N] {
        let mut key = [0u8; N];
        let mut counter: u32 = 1;
        for chunk in key.chunks_mut(32) {
            let digest = sha2::Sha256::new()
            .update(z)
            .update(&counter.to_be_bytes())
            .update(shared_info)
            .finalize();
            counter += 1;
            let n = chunk.len();
            chunk[..n].copy_from_slice(&digest[..n]);
        }
        key
    }
}
