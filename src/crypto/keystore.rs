use std::error::Error;
use std::fmt;

use aes::cipher::{KeyIvInit, StreamCipher};
use aes::Aes128;
use ctr::Ctr64LE;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use uuid::Uuid;

use crate::keytools::{generate_random_bytes, get_address_from_private_key};
use crate::util::generate_mac;

use super::{pbkdf2, scrypt};

type Aes128Ctr64LE = Ctr64LE<Aes128>;

#[derive(Debug)]
pub enum KDFType {
    PBKDF2,
    Scrypt,
}

impl fmt::Display for KDFType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", format!("{:?}", self).to_lowercase())
    }
}

impl Serialize for KDFType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match *self {
            KDFType::PBKDF2 => "pbkdf2",
            KDFType::Scrypt => "scrypt",
        })
    }
}

impl<'de> Deserialize<'de> for KDFType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Ok(match s.as_str() {
            "pbkdf2" => KDFType::PBKDF2,
            "scrypt" => KDFType::Scrypt,
            _ => unimplemented!(),
        })
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyStoreV3 {
    address: String,
    id: String,
    version: u32,
    crypto: Crypto,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Crypto {
    cipher: String,
    #[serde(rename = "ciphertext")]
    cipher_text: String,
    kdf: KDFType,
    mac: String,
    #[serde(rename = "cipherparams")]
    cipher_params: CipherParams,
    #[serde(rename = "kdfparams")]
    kdf_params: KDFParams,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct CipherParams {
    iv: String,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KDFParams {
    n: u32,
    c: u32,
    r: u32,
    p: u32,
    #[serde(rename = "dklen")]
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
    t: KDFType,
) -> Result<String, Box<dyn Error>> {
    let address = get_address_from_private_key(private_key)?;
    let iv = generate_random_bytes(16);
    let salt = generate_random_bytes(32);

    let derived_key = match t {
        KDFType::PBKDF2 => pbkdf2::get_derived_key(passphrase, &salt, 262144, 32)?,
        KDFType::Scrypt => scrypt::get_derived_key(passphrase, &salt, 8192, 8, 1, 32)?,
    };

    let encrypt_key = &derived_key[0..16];

    let mut cipher_text = private_key.to_vec();
    let mut cipher = Aes128Ctr64LE::new(encrypt_key.into(), iv[0..16].into());
    cipher.apply_keystream(&mut cipher_text);

    let mac = generate_mac(&derived_key, &cipher_text, &iv);

    let cp = CipherParams {
        iv: hex::encode(iv),
    };

    let kp = KDFParams::new(hex::encode(salt));

    let crypto = Crypto {
        cipher: "aes-128-ctr".to_string(),
        cipher_params: cp,
        cipher_text: hex::encode(cipher_text),
        kdf: t,
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
    let kv = serde_json::from_str::<KeyStoreV3>(json)?;

    let cipher_text = hex::decode(&kv.crypto.cipher_text)?;
    let iv = hex::decode(kv.crypto.cipher_params.iv)?;
    let kdf_params = kv.crypto.kdf_params;
    let kdf = kv.crypto.kdf;

    let derived_key = match kdf {
        KDFType::PBKDF2 => pbkdf2::get_derived_key(
            passphrase.as_bytes(),
            &hex::decode(kdf_params.salt)?,
            262144,
            32,
        )?,
        KDFType::Scrypt => scrypt::get_derived_key(
            passphrase.as_bytes(),
            &hex::decode(kdf_params.salt)?,
            8192,
            8,
            1,
            32,
        )?,
    };

    let mac = hex::encode(generate_mac(&derived_key, &cipher_text, &iv));

    if mac.to_lowercase() != kv.crypto.mac.to_lowercase() {
        return Err(String::from("Failed to decrypt.").into());
    }

    let encrypt_key = &derived_key[0..16];

    let mut private_key = cipher_text.to_vec();
    let mut cipher = Aes128Ctr64LE::new(encrypt_key.into(), iv[0..16].into());
    cipher.apply_keystream(&mut private_key);

    Ok(hex::encode(&private_key))
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
            KDFType::PBKDF2,
        )
        .unwrap();
        println!("{:?}", kv);
    }

    #[test]
    fn test_decrypt_private_key() {
        let json = "{\"address\":\"b5c2cdd79c37209c3cb59e04b7c4062a8f5d5271\",\"id\":\"27643f03-7aa1-46a4-9c31-cede013023ac\",\"version\":3,\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"2566c5a9b8fee98efead1116087a0bccebcbea4e5f501f79875f89705bc036d4\",\"kdf\":\"pbkdf2\",\"mac\":\"f5d06c279a2430b59c8a32cc80ef79c7ade3ba7fbef4c07cf3ab6d0163afadd6\",\"cipherparams\":{\"iv\":\"70646b487868616d544c634d55323634\"},\"kdfparams\":{\"n\":8192,\"c\":262144,\"r\":8,\"p\":1,\"dklen\":32,\"salt\":\"564871524a367a474f77664c7175734d4a45416b76534b43466e6d304c346c68\"}}}";
        let private_key = decrypt_private_key(json, "xiaohuo").unwrap();

        assert_eq!(
            private_key.to_lowercase(),
            "24180e6b0c3021aedb8f5a86f75276ee6fc7ff46e67e98e716728326102e91c9"
        )
    }
}
