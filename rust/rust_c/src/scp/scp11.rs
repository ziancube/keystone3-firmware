use std::io::Read;

use super::errors::Result;

use bytes::{Buf, BufMut, Bytes, BytesMut, TryGetError};
use thiserror;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum TaggedError {
    #[error("Tag not match, want: {want}, got: {got}")]
    TagNotMatch { want: u16, got: u16 },
    #[error("Length not enough")]
    LengthNotEnough,
    #[error("Unexpected length")]
    UnexpectedLength,
    #[error("Unexpected content")]
    UnexpectedContent,
    #[error("Invalid string {0}")]
    InvalidString(String),
}

impl From<TryGetError> for TaggedError {
    fn from(_: TryGetError) -> Self {
        TaggedError::LengthNotEnough
    }
}

type TaggedResult<T> = core::result::Result<T, TaggedError>;

pub trait Decode: Sized {
    fn decode(buf: &mut Bytes) -> TaggedResult<Self>;
}
pub trait Encode: Sized {
    fn encode(&self, buf: &mut BytesMut);
}

fn decode<T>(buf: &mut Bytes) -> TaggedResult<T>
where
    T: Decode,
{
    T::decode(buf)
}

fn try_decode<const TAG: u16, T>(buf: &mut Bytes) -> TaggedResult<Option<Tagged<TAG,T>>>
where 
    Tagged<TAG, T>: Decode,
{
    // 不要消耗
    let tag = match TAG {
        0..=0xff => {
            buf[0] as u16
        }
        _ => {
            if buf.remaining() < 2 {
                return Err(TaggedError::LengthNotEnough);
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

fn decode_length(buf: &mut Bytes) -> TaggedResult<usize> {
    let n = buf.try_get_u8()? as usize;
    match n {
        0..=127 => Ok(n as usize),
        _ => {
            let size = (n & 0x7f) as usize;
            if buf.remaining() < size {
                return Err(TaggedError::LengthNotEnough);
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
fn verify_tag(tag: u16, buf: &mut Bytes) -> TaggedResult<()> {
    let _tag = if tag <= 0xFF {
        buf.try_get_u8()? as u16
    } else {
        buf.try_get_u16()?
    };
    if tag != _tag {
        return Err(TaggedError::TagNotMatch {
            want: tag,
            got: _tag,
        });
    }

    Ok(())
}

impl<const TAG: u16, T> Tagged<TAG, T> {
    fn encode_length(length: usize, buf: &mut BytesMut) {
        encode_length(length, buf);
    }
    fn decode_length(buf: &mut Bytes) -> TaggedResult<usize> {
        decode_length(buf)
    }
    fn encode_tag(buf: &mut BytesMut) {
        encode_tag(TAG, buf);
    }
    fn verify_tag(buf: &mut Bytes) -> TaggedResult<()> {
        verify_tag(TAG, buf)
    }
}

/// ()
impl<const TAG: u16> Decode for Tagged<TAG, ()> {
    fn decode(buf: &mut Bytes) -> TaggedResult<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size != 0 {
            return Err(TaggedError::UnexpectedContent);
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
impl From<core::str::Utf8Error> for TaggedError {
    fn from(value: core::str::Utf8Error) -> Self {
        TaggedError::InvalidString(value.to_string())
    }
}

impl<const TAG: u16> Decode for Tagged<TAG, String> {
    fn decode(buf: &mut Bytes) -> TaggedResult<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if buf.remaining() < size {
            return Err(TaggedError::LengthNotEnough);
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
    fn decode(buf: &mut Bytes) -> TaggedResult<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        match size {
            1 => {
                let ku = buf.try_get_u8()?;
                if ku != 0x82 {
                    return Err(TaggedError::UnexpectedContent);
                }
                Ok(Self {
                    value: KeyUsage::SignatureVerification,
                })
            }
            2 => {
                let ku = buf.try_get_u16()?;
                if ku != 0x0080 {
                    return Err(TaggedError::UnexpectedContent);
                }
                Ok(Self {
                    value: KeyUsage::Agreement,
                })
            }
            _ => Err(TaggedError::UnexpectedLength),
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
    fn decode(buf: &mut Bytes) -> TaggedResult<Self> {
        // `BCD` format `YYYYMMDD`
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size != 4 {
            return Err(TaggedError::UnexpectedLength);
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
        Self::encode_length(6, buf);

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
    fn decode(buf: &mut Bytes) -> TaggedResult<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size != 1 {
            return Err(TaggedError::UnexpectedLength);
        }
        let v = buf.try_get_u8()?;
        if v > KeyParamterReference::SM2 as u8 {
            return Err(TaggedError::UnexpectedContent);
        }
        let kpr = unsafe { ::std::mem::transmute(v) };
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

/// Bytes
impl<const TAG: u16> Decode for Tagged<TAG, Bytes> {
    fn decode(buf: &mut Bytes) -> TaggedResult<Self> {
        Self::verify_tag(buf)?;
        let size = Self::decode_length(buf)?;
        if size > buf.remaining() {
            return Err(TaggedError::LengthNotEnough);
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
    pub q: Tagged<0xB0, Bytes>,
    pub kpr: Tagged<0xF0, KeyParamterReference>,
}

impl<const TAG: u16> Decode for Tagged<TAG, PublicKeyData> {
    fn decode(buf: &mut Bytes) -> TaggedResult<Self> {
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
    pub sig: Tagged<0x5F37, Bytes>,
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
    fn decode(buf: &mut Bytes) -> TaggedResult<Self> {
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

#[cfg(test)]
mod tests {
    extern crate std;
    use crate::scp::scp11::{Certificate, Decode};
    use bytes::Bytes;
    use hex;

    #[test]
    fn parser_certificate() {
        let bytes = hex::decode("7F2181DB9310434552545F4F43455F45434B41303031420D6A75626974657277616C6C65745F200D6A75626974657277616C6C6574950200805F2504202005255F2404202505245300BF20007F4946B0410408CCB49EB91057287572E68706F3CB4C27CE19AD94C40B2A37C594E51BC09EAD96349466306C5863F6E8BEB3F0EA99711848163201BFE8C788433D45816469E5F001005F37473045022100879EEB7EE0962B44BD3D8701161A263477CC2F08D7681AF8546FBC17EB3E996502201600FA7A741B0EFE7C143D73713E8031AFBB3F1C0B6D69048020D273E48AAF5E").unwrap();
        let mut buf = Bytes::from(bytes);

        let cert = Certificate::decode(&mut buf).unwrap();
        _ = cert;
    }

    #[test]
    fn parser_certificate_without_bf20() {
        let bytes = hex::decode("7f2181d49310434152444b5032333337303030303031420654506c6974655f2010434152444b50323333373030303030319501825f2504202310095f24042028100753007f4946b04104e7ec073d0ec376cc0d2fcf495289f3ff4dd28b1337802139297338951af8aba08baabbd0fc040e7e17cadfc14865f1636a345aed5664af412b79b22667771c17f001005f374830460221009bb26955499317cbd2764b5248df3a9ea435c6478b9d80ef325a226787adad6b022100f509bb9e749c7af0d93850f5dac0a96df3b88082c84557f1f458c81db0df01f2").unwrap();
        let mut buf = Bytes::from(bytes);

        let cert = Certificate::decode(&mut buf).unwrap();
        _ = cert;
    }
}
