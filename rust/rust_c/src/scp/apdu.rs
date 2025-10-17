use core::ops::Deref;
use super::errors::ScpError;
use super::errors::Result;

pub struct APDU {
    pub(crate) cla: u8,
    pub(crate) ins: u8,
    pub(crate) p1: u8,
    pub(crate) p2: u8,
    pub(crate) data: Option<Vec<u8>>,
    pub(crate) le: Option<u8>,
}

impl APDU {
    pub fn to_vec(&self) -> Vec<u8> {
        let mut bytes = self.header().to_vec();
        if let Some(data) = &self.data {
            // only support lc < 256
            let lc = data.len() as u8;
            bytes.push(lc);
            bytes.extend(data);
        }

        if let Some(le) = self.le {
            bytes.push(le);
        }

        bytes
    }

    pub fn header(&self) -> [u8;4] {
        [self.cla, self.ins, self.p1, self.p2]
    }
}

pub struct APDUResponse(Vec<u8>);

impl APDUResponse {
    pub fn new(value: Vec<u8>) -> APDUResponse {
        Self(value)
    }

    pub fn sw(&self) -> u16 {
        let le = self.len();
        let sw1 = self[le-2];
        let sw2 = self[le-1];
        u16::from_be_bytes([sw1, sw2])
    }

    pub fn data(&self) -> Option<&[u8]> {
        match self.len() {
            x if x <= 2 => None,
            le => Some(&self[..(le-2)])
        }
    }

    pub fn is_success(&self) -> bool {
        self.sw() == 0x9000
    }
}

impl TryFrom<Vec<u8>> for APDUResponse {
    type Error = ScpError;
    fn try_from(value: Vec<u8>) -> Result<Self> {
        match value.len() {
            x if x < 2 => Err(ScpError::InvalidLength),
            _ => Ok(Self(value))
        }
    }
}

impl Deref for APDUResponse {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

pub(crate) struct EncryptedAPDUResponse<'a> (&'a [u8]);

impl <'a> EncryptedAPDUResponse<'a> {
    pub fn sw(&self) -> u16 {
        let le = self.len();
        let sw1 = self[le-2];
        let sw2 = self[le-1];
        u16::from_be_bytes([sw1, sw2])
    }

    pub fn mac(&self) -> Option<&[u8]> {
        let le = self.len();
        // one block encrypt + mac + sw
        if le < 16 + 8 + 2 {
            return None;
        }
        Some(&self[(le-8-2)..(le-2)])
    }

    pub fn data(&self) -> Option<&[u8]> {
        let le = self.len();
        if le < 16 + 8 + 2 {
            return None;
        }
        Some(&self[..(le-8-2)])
    }

    pub fn is_success(&self) -> bool {
        self.sw() == 0x9000
    }
}

impl <'a> TryFrom<&'a [u8]> for EncryptedAPDUResponse<'a> {
    type Error = ScpError;
    fn try_from(value: &'a [u8]) -> Result<Self> {
        match value.len() {
            // one block encrypted data + mac + sw
            x if x < 2 => Err(ScpError::InvalidLength),
            _ => Ok(Self(value))
        }
    }
}

impl <'a>Deref for EncryptedAPDUResponse<'a> {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

#[macro_export]
macro_rules! apdu {
    // 匹配带有 `data` 和 `le` 的完整形式
    ($cla:expr, $ins:expr, $p1:expr, $p2:expr, data: $data:expr, le: $le:expr) => {
        APDU {
            cla: $cla,
            ins: $ins,
            p1: $p1,
            p2: $p2,
            data: Some($data),
            le: Some($le),
        }
    };
    // 匹配只有 `data` 的形式
    ($cla:expr, $ins:expr, $p1:expr, $p2:expr, data: $data:expr) => {
        APDU {
            cla: $cla,
            ins: $ins,
            p1: $p1,
            p2: $p2,
            data: Some($data),
            le: None,
        }
    };
    // 匹配只有 `le` 的形式
    ($cla:expr, $ins:expr, $p1:expr, $p2:expr, le: $le:expr) => {
        APDU {
            cla: $cla,
            ins: $ins,
            p1: $p1,
            p2: $p2,
            data: None,
            le: Some($le),
        }
    };
    // 匹配没有 `data` 和 `le` 的简化形式
    ($cla:expr, $ins:expr, $p1:expr, $p2:expr) => {
        APDU {
            cla: $cla,
            ins: $ins,
            p1: $p1,
            p2: $p2,
            data: None,
            le: None,
        }
    };
}
