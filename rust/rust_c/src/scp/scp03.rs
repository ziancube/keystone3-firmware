use cbc::{
    self,
    cipher::{BlockDecryptMut, BlockEncryptMut, KeyInit, KeyIvInit},
};
use cmac::{Cmac, Mac};
use aes;
use aes::cipher::block_padding::Iso7816;
use super::apdu::{APDU, APDUResponse};
use super::errors::{ScpError, Result};

type AesCbcEnc = cbc::Encryptor<aes::Aes128>;
type AesCbcDec = cbc::Decryptor<aes::Aes128>;
type AesCmac = Cmac<aes::Aes128>;


pub struct Scp03 {
    pub counter: u32,
    pub s_enc: [u8; 16],
    pub s_mac: [u8; 16],
    pub s_rmac: [u8; 16],
    pub mac_chain: [u8; 16],
}

enum IcvType {
    CEncryption,
    REncryption,
}

impl Scp03 {
    pub fn new() -> Scp03 {
        Scp03 {
            counter: 0,
            s_enc: [0u8; 16],
            s_mac: [0u8; 16],
            s_rmac: [0u8; 16],
            mac_chain: [0u8; 16],
        }
    }

    pub fn build_apdu(&mut self, apdu: &mut APDU) {
        match &apdu.data {
            None => {}
            Some(data) => {
                let data = self.encrypt(&data);
                apdu.data = Some(data);
            }
        };

        let mac = self.cmac(apdu);
        let mut data = apdu.data.clone().unwrap_or_default();
        data.extend(&mac);
        apdu.data = Some(data);
        self.counter += 1;
    }

    pub fn parse_response(&self, resp: &[u8]) -> Result<APDUResponse> {
        // mac and sw
        let len = resp.len();
        if len < 18 {
            return Err(ScpError::InvalidLength);
        }

        let mac1 = self.rmac(resp);

        let mac2 = &resp[(len - 18)..(len - 2)];
        if mac1 != mac2 {
            return Err(ScpError::MacNotMatch);
        }

        let mut raw = resp[..(len - 18)].to_vec();
        raw.extend(&resp[(len - 2)..]);

        APDUResponse::try_from(raw)
    }

    fn encrypt(&self, data: &[u8]) -> Vec<u8> {
        // scp03 6.2.6
        AesCbcEnc::new(&self.s_enc.into(), &self.icv(IcvType::CEncryption).into())
            .encrypt_padded_vec_mut::<Iso7816>(&data)
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let decrypter = AesCbcDec::new(&self.s_enc.into(), &self.icv(IcvType::REncryption).into());
        Ok(decrypter.decrypt_padded_vec_mut::<Iso7816>(&data)?)
    }

    fn cmac(&mut self, apdu: &mut APDU) -> [u8; 16] {
        // scp03 6.2.4
        apdu.cla |= 0x04;
        let mut bytes = self.mac_chain.to_vec();
        bytes.extend(&apdu.header());
        match &apdu.data {
            None => {
                let lc = 0 + 16;
                bytes.push(lc);
            }
            Some(data) => {
                let lc = data.len() as u8 + 16;
                bytes.push(lc);
                bytes.extend(data);
            }
        }

        let mac = <AesCmac as Mac>::new(&self.s_mac.into())
            .chain_update(&bytes)
            .finalize();
        // update mac chain
        self.mac_chain = mac.clone().into_bytes().into();
        mac.into_bytes().into()
    }

    fn rmac(&self, resp: &[u8]) -> [u8; 16] {
        // scp03 6.2.5
        // total len [data] rmac sw
        let len = resp.len();
        // skip r-mac
        let mut raw = resp[..(len - 18)].to_vec();
        raw.extend(&resp[(len - 2)..]);

        let mac = <AesCmac as Mac>::new(&self.s_rmac.into())
            .chain_update(&self.mac_chain)
            .chain_update(&raw);
        mac.finalize().into_bytes().into()
    }

    fn icv(&self, icv_type: IcvType) -> [u8; 16] {
        let mut block = [0u8; 16];
        block[12..].copy_from_slice(&self.counter.to_be_bytes());
        match icv_type {
            IcvType::REncryption => block[0] = 0x80,
            _ => {}
        }
        aes::Aes128::new(&self.s_enc.into()).encrypt_block_mut(&mut block.into());
        block
    }
}
