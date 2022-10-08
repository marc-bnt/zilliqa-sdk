use std::error::Error;

use crate::{
    crypto::keystore::{KDFType, KeyStore},
    keytools::{get_address_from_public_key, get_public_key_from_private_key},
};

pub struct Account {
    private_key: Vec<u8>,
    public_key: Vec<u8>,
    address: String,
}

impl Account {
    pub fn new(private_key: Vec<u8>) -> Self {
        let public_key = get_public_key_from_private_key(&private_key, true).unwrap();
        let address = get_address_from_public_key(&public_key).unwrap();
        Self {
            private_key,
            public_key,
            address,
        }
    }
}

pub fn from_file(file: &str, passphrase: &str) -> Result<Account, Box<dyn Error>> {
    let ks = KeyStore::default();
    let private_key = ks.decrypt_private_key(file, passphrase)?;

    Ok(Account::new(hex::decode(private_key)?))
}

pub fn to_file(private_key: &str, passphrase: &str, t: KDFType) -> Result<String, Box<dyn Error>> {
    let ks = KeyStore::default();
    let file = ks.encrypt_private_key(&hex::decode(private_key)?, passphrase.as_bytes(), t)?;

    Ok(file)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FILE: &str = "{\"address\":\"b5c2cdd79c37209c3cb59e04b7c4062a8f5d5271\",\"id\":\"27643f03-7aa1-46a4-9c31-cede013023ac\",\"version\":3,\"crypto\":{\"cipher\":\"aes-128-ctr\",\"ciphertext\":\"2566c5a9b8fee98efead1116087a0bccebcbea4e5f501f79875f89705bc036d4\",\"kdf\":\"pbkdf2\",\"mac\":\"f5d06c279a2430b59c8a32cc80ef79c7ade3ba7fbef4c07cf3ab6d0163afadd6\",\"cipherparams\":{\"iv\":\"70646b487868616d544c634d55323634\"},\"kdfparams\":{\"n\":8192,\"c\":262144,\"r\":8,\"p\":1,\"dklen\":32,\"salt\":\"564871524a367a474f77664c7175734d4a45416b76534b43466e6d304c346c68\"}}}";

    #[test]
    fn test_to_file() {
        assert!(to_file(
            "24180e6b0c3021aedb8f5a86f75276ee6fc7ff46e67e98e716728326102e91c9",
            "xiaohuo",
            KDFType::PBKDF2
        )
        .is_ok());
    }

    #[test]
    fn test_from_file() {
        let account = from_file(FILE, "xiaohuo").unwrap();
        assert_eq!(
            hex::encode(account.private_key),
            "24180e6b0c3021aedb8f5a86f75276ee6fc7ff46e67e98e716728326102e91c9"
        )
    }
}
