#[cfg(test)]
mod tests {
    use core::time::Duration;

    use crate::scp::apdu::{APDUResponse, APDU};
    use crate::scp::scp11::{decode, Certificate, Decode, Scp11, Tagged};
    use bytes::Bytes;
    use hex;
    use p256::ecdsa::signature::hazmat::PrehashVerifier;
    use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
    use p256::elliptic_curve::ecdh::diffie_hellman;
    use pcsc;

    use log::{debug, info};
    use simple_logger::SimpleLogger;

    use crate::apdu;

    /// external c function
    #[no_mangle]
    pub extern "C" fn p256_load_sig_from_der(der: *const u8, der_len: usize, sig: *mut u8) -> i32 {
        let der_slice = unsafe { std::slice::from_raw_parts(der, der_len) };

        let _sig = match Signature::from_der(der_slice) {
            Ok(sig) => sig,
            Err(_) => return 1,
        };
        let r = _sig.r().to_bytes();
        let s = _sig.s().to_bytes();
        unsafe {
            std::ptr::copy(r.as_ptr(), sig, 32);
            std::ptr::copy(s.as_ptr(), sig.add(32), 32);
        }
        0
    }
    #[no_mangle]
    pub extern "C" fn p256_verify_signature(
        pk: *const u8,
        digest: *const u8,
        sig: *const u8,
    ) -> i32 {
        let pk_slice = unsafe { std::slice::from_raw_parts(pk, 65) };
        let sig_slice = unsafe { std::slice::from_raw_parts(sig, 64) };
        let digest_slice = unsafe { std::slice::from_raw_parts(digest, 32) };

        let pk = match VerifyingKey::from_sec1_bytes(pk_slice) {
            Ok(pk) => pk,
            Err(_) => return 1,
        };
        let sig = match Signature::from_slice(sig_slice) {
            Ok(sig) => sig,
            Err(_) => return 1,
        };
        match pk.verify_prehash(digest_slice, &sig) {
            Ok(_) => 0,
            Err(_) => 1,
        }
    }
    #[no_mangle]
    pub extern "C" fn p256_gen_keypair(sk: *mut u8, pk: *mut u8) -> i32 {
        // let _sk = SigningKey::random(&mut OsRng);
        let _sk = SigningKey::from_slice(&[0x11; 32]).unwrap();
        let _pk = VerifyingKey::from(&_sk);

        let sk_bytes = _sk.to_bytes();
        let pk_bytes = _pk.to_sec1_bytes();
        info!("esk: {}", hex::encode(&sk_bytes));
        info!("epk: {}", hex::encode(&pk_bytes));

        unsafe {
            std::ptr::copy(sk_bytes.as_ptr(), sk, sk_bytes.len());
            std::ptr::copy(pk_bytes.as_ptr(), pk, pk_bytes.len());
        }

        0
    }
    #[no_mangle]
    pub extern "C" fn p256_ecdh(sk: *const u8, pk: *const u8, key: *mut u8) -> i32 {
        let sk_slice = unsafe { std::slice::from_raw_parts(sk, 32) };
        let pk_slice = unsafe { std::slice::from_raw_parts(pk, 65) };
        let sk = SigningKey::from_slice(sk_slice).expect("SK");
        let pk = VerifyingKey::from_sec1_bytes(pk_slice).expect("PK");
        let shared = diffie_hellman(sk.as_nonzero_scalar(), pk.as_affine());
        unsafe {
            std::ptr::copy(shared.raw_secret_bytes().as_ptr(), key, 32);
        }
        0
    }

    /// external c function end
    static INIT: std::sync::Once = std::sync::Once::new();
    fn init_logger() {
        INIT.call_once(|| {
            SimpleLogger::new().init().unwrap();
        });
    }

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
    #[test]
    fn test_scp() {
        init_logger();

        let card = connect_reader();

        select(&card);
        let scp11 = open_secure_channel(&card);

        reset_wallet(&card, &scp11);
        check_pin_state(&card, &scp11);
        reset_pin(&card, &scp11);
        get_pin_retry_times(&card, &scp11);
        change_pin(&card, &scp11);
        verify_pin(&card, &scp11);
        check_pin_state(&card, &scp11);
        test_read_write(&card, &scp11);
        logout(&card, &scp11);
        get_sn(&card, &scp11);
        reset_wallet(&card, &scp11);
    }

    fn connect_reader() -> pcsc::Card {
        let ctx = pcsc::Context::establish(pcsc::Scope::User).expect("PCSC establish");
        let mut readers_buf = [0u8; 2048];

        let readers = ctx
            .list_readers(&mut readers_buf)
            .expect("PCSC list readers");

        let readers: Vec<_> = readers.collect();

        let reader = if readers.len() < 1 {
            panic!("No reader");
        } else if readers.len() > 1 {
            info!("more than one reader, use the first");
            for (i, r) in readers.iter().enumerate() {
                info!("\t{}: {:?}", i, r);
            }
            readers[0]
        } else {
            readers[0]
        };

        info!("use {:?}", reader);

        let card = ctx
            .connect(reader, pcsc::ShareMode::Shared, pcsc::Protocols::ANY)
            .expect("PCSC connect reader");
        card
    }

    fn transmit_apdu(card: &pcsc::Card, apdu: &APDU) -> APDUResponse {
        let apdu = &apdu.to_vec();
        debug!("apdu: {}", hex::encode(apdu));
        let mut buf = [0u8; 512];
        let resp = card.transmit(apdu, &mut buf).expect("PCSC card transmit");
        debug!("resp: {}", hex::encode(resp));
        APDUResponse::new(resp.to_vec())
    }

    fn transmit_safe_apdu(card: &pcsc::Card, scp11: &Scp11, apdu: APDU) -> APDUResponse {
        info!("raw apdu: {}", hex::encode(&apdu.to_vec()));
        let apdu = scp11.encrypt_apdu(apdu).expect("encrypt apdu");
        let resp = transmit_apdu(card, &apdu);
        let resp = scp11.decrypt_apdu_response(&resp).expect("decrypt response");
        if !resp.is_success() {
            debug!("sw: {:04x}", resp.sw());
            panic!("apdu response failed");
        }
        info!("raw resp: {}", hex::encode(&resp.to_vec()));
        resp
    }

    fn select(card: &pcsc::Card) {
        static AID: &str = &"54502d6261636b757001";
        let aid = hex::decode(AID).unwrap();
        info!("select applet: {}", AID);
        let apdu = apdu!(0x00, 0xa4, 0x04, 0x00, data: aid);
        let resp = transmit_apdu(card, &apdu);
        if !resp.is_success() {
            panic!("select applet failed");
        }
    }

    struct OCE {
        pub sk_oce: [u8;32],
        pub pk_ca_klcc: [u8; 65],
        pub cert_oce: Vec<u8>,
        pub host_id: String,
    }
    fn load_oce_config() -> OCE {
        let content = std::fs::read("OCE.settings").expect("read OCE.settings");
        let obj: serde_json::Value = serde_json::from_slice(&content).expect("deserialize OCE settings");

        let scp11c = &obj["SCP11c"];
        let host_id = &scp11c["HostID"];

        let oce = &scp11c["OCE"][1];
        let sd = &scp11c["SD"][0];

        let cert_oce = &oce[0];
        let sk_oce = &oce[2];
        let pk_ca_klcc = &sd[1];

        let v = sk_oce.as_str().expect("decode sk.oce");
        let sk_oce:[u8; 32] = hex::decode(&v).expect("decode sk.oce").try_into().expect("decode sk.oce");

        let v = pk_ca_klcc.as_str().expect("decode pk.ca.klcc");
        let pk_ca_klcc: [u8; 65] = hex::decode(&v).expect("decode pk.ca.klcc").try_into().expect("decode pk.ca.klcc");

        let v = cert_oce.as_str().expect("decode cert.oce");
        let cert_oce: Vec<u8> = hex::decode(&v).expect("decode cert.oce").to_vec();
        let host_id = host_id.to_string();

        OCE {
            sk_oce: sk_oce,
            pk_ca_klcc: pk_ca_klcc,
            cert_oce: cert_oce,
            host_id: host_id,
        }
    }

    fn open_secure_channel(card: &pcsc::Card) -> Scp11 {
        info!("step 0. get device certificate");
        let apdu = apdu!( 0x80, 0xCA, 0xBF, 0x21, data: vec![0xA6, 0x04, 0x83, 0x02, 0x15, 0x18]);
        let resp = transmit_apdu(card, &apdu);

        let mut buf = Bytes::from(resp.data().expect("empty response").to_vec());
        let cert_store: Tagged<0xBF21, Vec<u8>> = decode(&mut buf).expect("decode cert store");
        let sd_cert_bytes = &cert_store.value;
        debug!("SD cert: {}", hex::encode(sd_cert_bytes));

        let mut buf = Bytes::from(cert_store.value.clone());
        let sd_cert = Certificate::decode(&mut buf).expect("SD cert");
        info!("SD CSN: {}", &sd_cert.sn.value);
        info!("SD subject: {}", &sd_cert.subject.value);

        info!("step 1. load sk.oce cert.oce pk.ca.klcc");
        let oce = load_oce_config();

        info!("SK.OCE: {}", hex::encode(&oce.sk_oce));
        info!("CERT.OCE: {}", hex::encode(&oce.cert_oce));
        info!("PK.CA.KLCC: {}", hex::encode(&oce.pk_ca_klcc));
        info!("HOST ID: {}", &oce.host_id);

        info!("step 2. setup scp11 client");
        let mut scp11 = Scp11::with_certs(oce.sk_oce, &oce.cert_oce, &oce.pk_ca_klcc, &sd_cert_bytes)
            .expect("scp11 client");

        info!("step 3. perform secure operation");
        let apdu = scp11.perform_secure_operation();
        _ = transmit_apdu(card, &apdu);

        info!("step 4. mutual authenticate");
        let apdu = scp11.mutual_authenticate(&oce.host_id);
        let resp = transmit_apdu(card, &apdu);

        info!("step 5. open secure channel");
        scp11.open_secure_channel(&resp.to_vec()).expect("open channel");

        info!("open secure channel success ");

        scp11
    }

    fn reset_wallet(card: &pcsc::Card, scp11: &Scp11) {
        info!("wallet reseting ...");
        let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: vec![0xdf, 0xfe, 0x02, 0x82, 0x05]);
        transmit_safe_apdu(card, scp11, apdu);
        info!("reset wallet success");
    }

    fn check_pin_state(card: &pcsc::Card, scp11: &Scp11) {
        info!("check pin state");
        let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data:vec![ 0xDF,0xFF, 0x02, 0x81, 0x05 ]);
        let resp = transmit_safe_apdu(card, scp11, apdu);
        let state = resp.data().expect("resp data")[0];
        info!("PIN state: {state:02x}");
        if state == 0x02 {
            info!("PIN is set? N");
        } else {
            info!("PIN is set? Y");
        }
    }

    fn reset_pin(card: &pcsc::Card, scp11: &Scp11) {
        info!("reset pin");
        let pin = "123456";
        let mut data = vec![0xdf, 0xfe, 0x0b, 0x82, 0x04, 0x08, 0x00, 0x06];
        data.extend(pin.as_bytes());
        let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: data);
        transmit_safe_apdu(card, scp11, apdu);
        info!("reset pin success");
    }

    fn get_pin_retry_times(card: &pcsc::Card, scp11: &Scp11) {
        info!("get pin retry times");

        // remained
        let data = vec![0xdf, 0xff, 0x02, 0x81, 0x02];
        let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: data);
        let resp = transmit_safe_apdu(card, scp11, apdu);
        let c = resp.data().expect("invalid response")[0];
        info!("PIN remained retry times: {}", c);

        // total
        let data = vec![0xdf, 0xff, 0x02, 0x81, 0x03];
        let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: data);
        let resp = transmit_safe_apdu(card, scp11, apdu);
        let c = resp.data().expect("invalid response")[0];
        info!("PIN max retry times: {}", c);
    }

    fn verify_pin(card: &pcsc::Card, scp11: &Scp11) {
        info!("verify pin");
        let pin = "123456";
        let mut data = vec![0x06];
        data.extend(pin.as_bytes());

        let apdu = apdu!(0x80, 0x20, 0x00, 0x00, data: data);
        let resp = transmit_safe_apdu(card, scp11, apdu);
        let sw = resp.sw();
        match sw {
            0x9000 => info!("verify pin success"),
            0x6c30..0x6c3f => info!("verify pin failed, retry times: {}", sw&0x0f),
            _ => info!("verify pin failed: {:04x}", sw),
        }
    }

    fn logout(card: &pcsc::Card, scp11: &Scp11) {
        info!("logout");
        let apdu = apdu!(0x80, 0x21, 0x00, 0x00);
        transmit_safe_apdu(card, scp11, apdu);
        info!("logout success");
    }

    fn change_pin(card: &pcsc::Card, scp11: &Scp11) {
        info!("change pin");
        let pin = "123456";
        let mut data = vec![0xdf, 0xfe, 0x11, 0x82, 0x04, 0x0e];
        // old pin LV
        data.push(pin.len() as u8);
        data.extend(pin.as_bytes());
        // new pin LV
        data.push(pin.len() as u8);
        data.extend(pin.as_bytes());

        let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: data);
        transmit_safe_apdu(card, scp11, apdu);
        info!("change pin success");
    }

    fn write_data(card: &pcsc::Card, scp11: &Scp11, slot: u8, data: &[u8]) {
        info!("write data");
        let apdu = apdu!(0x80, 0x3b, 0x00, slot, data: data.to_vec());
        transmit_safe_apdu(card, scp11, apdu);
        info!("write data at {} success", slot);
    }

    fn read_data(card: &pcsc::Card, scp11: &Scp11, slot: u8) -> Vec<u8> {
        info!("read data");
        let apdu = apdu!(0x80, 0x4b, 0x00, slot);
        let resp = transmit_safe_apdu(card, scp11, apdu);
        let data = resp.data().expect("invalid response");
        info!("read data at {} success", slot);
        info!("data: {}", hex::encode(data));
        data.to_vec()
    }

    fn delete_data(card: &pcsc::Card, scp11: &Scp11, slot: u8) {
        info!("delete data");
        let apdu = apdu!(0x80, 0x7a, 0x00, slot);
        transmit_safe_apdu(card, scp11, apdu);
        info!("delete data at {} success", slot);
    }

    fn test_read_write(card: &pcsc::Card, scp11: &Scp11) {
        for slot in 0u8..4 {
            let data = vec![slot; 231];
            write_data(card, scp11, slot, &data);
            show_store_bitmap(card, scp11);
            if is_stored_in_slot(card, scp11, slot) {
                info!("have stored in : {}", slot);
            } else {
                info!("not stored in : {}", slot);
            }
            // std::thread::sleep(Duration::from_secs(1));
            let data2 = read_data(card, scp11, slot);
            if data == data2 {
                info!("write/read data success");
            } else {
                info!("write/read data failed");
            }
        }

        for slot in 0u8..4 {
            show_store_bitmap(card, scp11);
            delete_data(card, scp11, slot);
        }
    }

    fn get_store_bitmap(card: &pcsc::Card, scp11: &Scp11) -> u64 {
        let apdu = apdu!(0x80, 0x6a, 0x00, 0x00);
        let resp = transmit_safe_apdu(card, scp11, apdu);
        let data = resp.data().expect("invalid store map");
        let mut data = data.to_vec();
        data.reverse();
        let mut bitmap: u64 = 0;
        for d in data {
            bitmap <<= 8;
            bitmap += d as u64;
        }
        bitmap
    }

    fn is_stored_in_slot(card: &pcsc::Card, scp11: &Scp11, slot: u8) -> bool {
        let bitmap = get_store_bitmap(card, scp11);
        return (bitmap & (1 << slot)) != 0
    }

    fn show_store_bitmap(card: &pcsc::Card, scp11: &Scp11) {
        let mut bitmap = get_store_bitmap(card, scp11);
        let mut map = Vec::with_capacity(41);
        for _ in 0..40 {
            if (bitmap & 1) != 0 {
                map.push(0x78u8); // x
            } else {
                map.push(0x30u8); // 0
            }
            bitmap >>= 1;
        }
        map.push(0);
        let map = String::from_utf8(map).expect("invalid map");
        info!("bitmap: {}", &map);
    }

    fn get_sn(card: &pcsc::Card, scp11: &Scp11) {
        info!("get sn");
        let data = vec![0xdf, 0xff, 0x02, 0x81, 0x01];
        let apdu = apdu!(0x80, 0xcb, 0x80, 0x00, data: data);
        let resp = transmit_safe_apdu(card, scp11, apdu);
        info!("get sn success");
        match resp.data() {
            None => info!("SN: <empty>"),
            Some(data) => {
                let sn = String::from_utf8(data.to_vec()).expect("invalid sn");
                info!("SN: {}", sn);
            }
        }
    }
}
