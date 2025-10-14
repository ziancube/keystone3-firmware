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
    pub fn to_bytes(&self) -> Vec<u8> {
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
        match self.0.len() {
            x if x <= 2 => None,
            le => Some(&self[..(le-2)])
        }
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
