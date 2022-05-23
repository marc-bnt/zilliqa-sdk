use std::error::Error;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use ctr::Ctr64LE;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::keytools::{generate_random_bytes, get_address_from_private_key};
use crate::util::generate_mac;

use super::scrypt::get_derived_key;

type Aes128Ctr64LE = Ctr64LE<Aes128>;

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyStoreV3 {
    address: String,
    id: String,
    version: u32,
    crypto: Crypto,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub struct Crypto {
    cipher: String,
    cipher_text: String,
    kdf: String,
    mac: String,
    cipher_params: CipherParams,
    kdf_params: KDFParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CipherParams {
    iv: String,
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(rename_all = "lowercase")]
pub struct KDFParams {
    n: u32,
    c: u32,
    r: u32,
    p: u32,
    dk_len: u32,
    salt: String,
}

impl KDFParams {
    pub fn new(salt: String) -> Self {
        Self {
            n: 8192,
            c: 262144,
            r: 8,
            p: 1,
            dk_len: 32,
            salt,
        }
    }
}

/// See https://github.com/ethereum/wiki/wiki/Web3-Secret-Storage-Definition.
pub fn encrypt_private_key(
    private_key: &[u8],
    passphrase: &[u8],
    t: u32,
) -> Result<String, Box<dyn Error>> {
    let address = get_address_from_private_key(private_key)?;
    let iv = generate_random_bytes(16);
    let salt = generate_random_bytes(32);

    let derived_key = get_derived_key(passphrase, &salt, 8192, 8, 1, 32)?;

    let encrypt_key = &derived_key[0..16];

    let mut cipher_text = private_key.to_vec();
    let mut cipher = Aes128Ctr64LE::new(encrypt_key.into(), iv[0..16].into());
    cipher.apply_keystream(&mut cipher_text);

    let mac = generate_mac(&derived_key, &cipher_text, &iv);

    let cp = CipherParams {
        iv: hex::encode(iv),
    };

    let kp = KDFParams::new(hex::encode(salt));

    let kdf = "scrypt";

    let crypto = Crypto {
        cipher: "aes-128-ctr".to_string(),
        cipher_params: cp,
        cipher_text: hex::encode(cipher_text),
        kdf: kdf.to_string(),
        kdf_params: kp,
        mac: hex::encode(mac),
    };

    let uid = Uuid::new_v4();
    let kv = KeyStoreV3 {
        address,
        crypto,
        id: uid.to_string(),
        version: 3,
    };

    Ok(serde_json::to_string(&kv).unwrap())
}

pub fn decrypt_private_key(json: &str, passphrase: &str) -> Result<String, Box<dyn Error>> {
    Ok("test".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_private_key() {
        let kv = encrypt_private_key(
            &hex::decode("24180e6b0c3021aedb8f5a86f75276ee6fc7ff46e67e98e716728326102e91c9")
                .unwrap(),
            "xiaohuo".as_bytes(),
            0,
        )
        .unwrap();
        println!("{:?}", kv);
    }

    #[test]
    fn test_decrypt_private_key() {
        let json = "{\"address\":\"b5c2cdd79c37209c3cb59e04b7c4062a8f5d5271\",\"id\":\"979daaf9-daf1-4002-8656-3cea134c9518\",\"version\":3,\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"26be10cdae0f397bdeead38e7fcc179957dd5e7ef95a1f0f53f37b7ad1355159\",\"kdf\":\"pbkdf2\",\"mac\":\"81d8e60bc08237e4ba154c0b27ad08562821d8c602ee8a492434128de48b66bc\",\"cipherparams\":{\"iv\":\"fc714ad6267c35a2df4cb3f8b8b3cc0d\"},\"kdfparams\":{\"n\":8192,\"c\":262144,\"r\":8,\"p\":1,\"dklen\":32,\"salt\":\"e22ef8a67a59299cee1532b6c6967bdfb0e75ca3c5dff852f9d8daa04683b0c1\"}}}";
        let private_key = decrypt_private_key(json, "xiaohuo").unwrap();

        assert_eq!(
            private_key.to_lowercase(),
            "24180e6b0c3021aedb8f5a86f75276ee6fc7ff46e67e98e716728326102e91c9"
        )
    }
}
