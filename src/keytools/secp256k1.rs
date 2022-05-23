use rand::random;
use secp256k1::rand::rngs::OsRng;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use sha2::{Digest, Sha256};
use std::error::Error;

pub fn generate_private_key() -> Result<Vec<u8>, Box<dyn Error>> {
    let mut rng = OsRng::new().expect("OsRng");
    let secret_key = SecretKey::new(&mut rng);

    Ok(secret_key.secret_bytes().to_vec())
}

pub fn get_public_key_from_private_key(
    private_key: &[u8],
    compress: bool,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let context = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key).unwrap();
    let public_key = PublicKey::from_secret_key(&context, &secret_key);

    match compress {
        true => Ok(public_key.serialize().to_vec()),
        false => Ok(public_key.serialize_uncompressed().to_vec()),
    }
}

pub fn get_address_from_public_key(public_key: &[u8]) -> Result<String, Box<dyn Error>> {
    let origin_address = hex::encode(Sha256::digest(public_key));
    Ok(origin_address[24..].to_string())
}

pub fn get_address_from_private_key(private_key: &[u8]) -> Result<String, Box<dyn Error>> {
    let public_key = get_public_key_from_private_key(private_key, true).unwrap();
    get_address_from_public_key(&public_key)
}

pub fn verify_private_key(private_key: &[u8]) -> bool {
    SecretKey::from_slice(private_key).is_ok()
}

pub fn generate_random_bytes(n: u32) -> Vec<u8> {
    (0..n).map(|_| random::<u8>()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_private_key() {
        let private_key = generate_private_key().unwrap();
        assert!(verify_private_key(&private_key));
    }

    #[test]
    fn test_get_public_key_from_private_key() {
        let private_key = "24180e6b0c3021aedb8f5a86f75276ee6fc7ff46e67e98e716728326102e91c9";
        let public_key =
            get_public_key_from_private_key(&hex::decode(private_key).unwrap(), false).unwrap();
        assert_eq!(hex::encode(public_key), "04163fa604c65aebeb7048c5548875c11418d6d106a20a0289d67b59807abdd299d4cf0efcf07e96e576732dae122b9a8ac142214a6bc133b77aa5b79ba46b3e20")
    }

    #[test]
    fn test_get_public_key_from_private_key_compressed() {
        let private_key = "af71626e38926401a6d2fd8fdf91c97f785b8fb2b867e7f8a884351e59ee9aa6";
        let public_key =
            get_public_key_from_private_key(&hex::decode(private_key).unwrap(), true).unwrap();
        assert_eq!(
            hex::encode(public_key),
            "0285c34ff11ea1e06f44d35afe3cc1748b6b122bb06df021a4767db4ef5fbcf1cd"
        )
    }

    #[test]
    fn test_get_address_from_public() {
        let public_key = "0246e7178dc8253201101e18fd6f6eb9972451d121fc57aa2a06dd5c111e58dc6a";
        let address = get_address_from_public_key(&hex::decode(public_key).unwrap()).unwrap();
        assert_eq!(address, "9bfec715a6bd658fcb62b0f8cc9bfa2ade71434a")
    }

    #[test]
    fn test_get_address_from_private_key() {
        let private_key = "24180e6b0c3021aedb8f5a86f75276ee6fc7ff46e67e98e716728326102e91c9";
        let address = get_address_from_private_key(&hex::decode(private_key).unwrap()).unwrap();
        assert_eq!(address, "b5c2cdd79c37209c3cb59e04b7c4062a8f5d5271")
    }

    #[test]
    fn test_generate_random_bytes() {
        let result = generate_random_bytes(32);
        println!("{:?}", result);
    }
}
