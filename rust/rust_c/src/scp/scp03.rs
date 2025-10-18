use core::cell::{Cell, RefCell};

use aes;
use aes::cipher::block_padding::{Iso7816, UnpadError};
use cbc::{
    self,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit},
};
use cipher::{generic_array::GenericArray, BlockEncrypt};
use cmac::{Cmac, Mac};

use crate::scp::apdu::EncryptedAPDUResponse;

use super::apdu::{APDUResponse, APDU};
use super::errors::{Result, ScpError};

type AesCbcEnc = cbc::Encryptor<aes::Aes128>;
type AesCbcDec = cbc::Decryptor<aes::Aes128>;
type AesCmac = Cmac<aes::Aes128>;

use ::log::debug;

impl From<UnpadError> for ScpError {
    fn from(_: UnpadError) -> Self {
        ScpError::InvalidPadding
    }
}

pub struct Scp03 {
    pub counter: Cell<u32>,
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    pub mac_chain: RefCell<[u8; 16]>,
}

enum IcvType {
    CEncryption,
    REncryption,
}

impl Scp03 {
    pub fn new() -> Scp03 {
        Scp03 {
            counter: Cell::new(1),
            s_enc: [0u8; 16],
            s_mac: [0u8; 16],
            s_rmac: [0u8; 16],
            mac_chain: RefCell::new([0u8; 16]),
        }
    }

    pub fn encrypt_apdu(&self, mut apdu: APDU) -> APDU {
        let data = match apdu.data {
            None => vec![],
            Some(data) => data,
        };
        apdu.data = Some(self.encrypt(&data));
        let mac = self.cmac(&mut apdu);
        let mut data = apdu.data.unwrap_or_default();
        data.extend(&mac);
        apdu.data = Some(data);

        apdu
    }

    pub fn decrypt_apdu_response(&self, resp: &[u8]) -> Result<APDUResponse> {
        // mac and sw
        let encrypt_resp = EncryptedAPDUResponse::try_from(resp)?;
        if !encrypt_resp.is_success() {
            return Ok(APDUResponse::try_from(resp.to_vec())?);
        }

        // check data and mac
        if encrypt_resp.mac().is_none() || encrypt_resp.data().is_none() {
            return Err(ScpError::InvalidLength);
        }

        let mac1 = self.rmac(&encrypt_resp);
        let mac2 = encrypt_resp.mac().unwrap();
        debug!("rmac1: {}", hex::encode(&mac1));
        debug!("rmac2: {}", hex::encode(&mac2));
        if mac1 != mac2 {
            return Err(ScpError::MacNotMatch);
        }

        let encrypted = encrypt_resp.data().unwrap();
        // decrypt data
        let mut data = self.decrypt(encrypted)?;
        // append [sw1, sw2]
        let len = encrypt_resp.len();
        data.extend(&encrypt_resp[(len - 2)..]);
        Ok(APDUResponse::try_from(data)?)
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        debug!("encrypt data: {}", hex::encode(data));
        AesCbcEnc::new(&self.s_enc.into(), &self.icv(IcvType::CEncryption).into())
            .encrypt_padded_vec_mut::<Iso7816>(&data)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // scp03 6.2.6
        let counter = self.counter.get();
        self.counter.set(counter + 1);
        let decrypter = AesCbcDec::new(&self.s_enc.into(), &self.icv(IcvType::REncryption).into());
        Ok(decrypter.decrypt_padded_vec_mut::<Iso7816>(&data)?)
    }

    fn cmac(&self, apdu: &mut APDU) -> [u8; 8] {
        // scp03 6.2.4
        apdu.cla |= 0x04;
        let mut bytes = self.mac_chain.borrow().to_vec();
        bytes.extend(&apdu.header());
        match &apdu.data {
            None => {
                let lc = 0 + 8;
                bytes.push(lc);
            }
            Some(data) => {
                let lc = data.len() as u8 + 8;
                bytes.push(lc);
                bytes.extend(data);
            }
        }
        debug!("cmac key: {}", hex::encode(&self.s_mac));
        debug!("cmac input: {}", hex::encode(&bytes));
        let mac = <AesCmac as Mac>::new(&self.s_mac.into())
            .chain_update(&bytes)
            .finalize();
        // update mac chain
        self.mac_chain.replace(mac.clone().into_bytes().into());
        // [u8;16] -> [u8; 8] resize mac
        mac.into_bytes()[..8].try_into().unwrap()
    }

    fn rmac(&self, resp: &EncryptedAPDUResponse) -> [u8; 8] {
        // scp03 6.2.5
        // total len [data] rmac sw
        let le = resp.len();
        let mac_chain = self.mac_chain.borrow();
        debug!("rmac key: {}", hex::encode(&self.s_rmac));
        debug!("rmac input1: {}", hex::encode(&mac_chain[..]));
        debug!("rmac input2: {}", hex::encode(&resp.data().unwrap()));
        let mac = <AesCmac as Mac>::new(&self.s_rmac.into())
            .chain_update(&mac_chain[..]) // mac chain
            .chain_update(&resp.data().unwrap()) // encrypted
            .chain_update(&resp[(le - 2)..]) // sw
            .finalize();

        // [u8;16] -> [u8; 8] resize mac
        mac.into_bytes()[..8].try_into().unwrap()
    }

    fn icv(&self, icv_type: IcvType) -> [u8; 16] {
        let mut block = [0u8; 16];
        block[12..].copy_from_slice(&self.counter.get().to_be_bytes());
        match icv_type {
            IcvType::REncryption => block[0] = 0x80,
            _ => {}
        }
        debug!("icv key: {}", hex::encode(&self.s_enc));
        debug!("icv input: {}", hex::encode(&block));
        let mut block = GenericArray::from(block);
        aes::Aes128::new(&self.s_enc.into()).encrypt_block(&mut block);
        block.into()
    }
}
