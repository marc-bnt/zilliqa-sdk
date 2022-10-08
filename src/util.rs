use hmac::{Hmac, Mac, NewMac};
use num_bigint::{BigInt, Sign, ToBigInt};
use sha2::{Digest, Sha256};
use std::cmp::Ordering;
use std::ops::BitAnd;

type HmacSha256 = Hmac<Sha256>;

pub fn pack(a: u32, b: u32) -> u32 {
    (a << 16) + b
}

pub fn sha_256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

pub fn hash_mac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(&data);
    mac.finalize().into_bytes().to_vec()
}

pub fn to_check_sum_address(address: &str) -> String {
    let address = address.to_string().to_lowercase().replace("0x", "");
    let hash = sha_256(&hex::decode(&address).unwrap());
    let mut ret = String::from("0x");

    for i in 0..address.len() {
        let char = address.chars().nth(i).unwrap();

        if "1234567890".to_string().contains(char) {
            ret.push(char);
        } else {
            let checker = BigInt::from_bytes_be(Sign::Plus, &hash)
                .bitand(2.to_bigint().unwrap().pow(255 - 6 * i as u32));

            if checker.cmp(&1.to_bigint().unwrap()) == Ordering::Less {
                ret.push(char.to_lowercase().next().unwrap());
            } else {
                ret.push(char.to_uppercase().next().unwrap());
            }
        }
    }

    ret
}

pub fn generate_mac(derived_key: &[u8], cipher_text: &[u8], iv: &[u8]) -> Vec<u8> {
    let mut buffer = Vec::new();
    buffer.extend_from_slice(&derived_key[16..]);
    buffer.extend_from_slice(&cipher_text[..]);
    buffer.extend_from_slice(&iv[..]);
    buffer.extend_from_slice("aes-128-ctr".as_bytes());
    hash_mac_sha256(derived_key, &buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_check_sum_address() {
        assert_eq!(
            to_check_sum_address("4BAF5FADA8E5DB92C3D3242618C5B47133AE003C"),
            "0x4BAF5faDA8e5Db92C3d3242618c5B47133AE003C"
        );

        assert_eq!(
            to_check_sum_address("448261915A80CDE9BDE7C7A791685200D3A0BF4E"),
            "0x448261915a80cdE9BDE7C7a791685200D3A0bf4E"
        );

        assert_eq!(
            to_check_sum_address("DED02FD979FC2E55C0243BD2F52DF022C40ADA1E"),
            "0xDed02fD979fC2e55c0243bd2F52df022c40ADa1E"
        );

        assert_eq!(
            to_check_sum_address("13F06E60297BEA6A3C402F6F64C416A6B31E586E"),
            "0x13F06E60297bea6A3c402F6f64c416A6b31e586e"
        );

        assert_eq!(
            to_check_sum_address("1A90C25307C3CC71958A83FA213A2362D859CF33"),
            "0x1a90C25307C3Cc71958A83fa213A2362D859CF33"
        );

        assert_eq!(
            to_check_sum_address("625ABAEBD87DAE9AB128F3B3AE99688813D9C5DF"),
            "0x625ABAebd87daE9ab128f3B3AE99688813d9C5dF"
        );

        assert_eq!(
            to_check_sum_address("36BA34097F861191C48C839C9B1A8B5912F583CF"),
            "0x36Ba34097f861191C48C839c9b1a8B5912f583cF"
        );

        assert_eq!(
            to_check_sum_address("D2453AE76C9A86AAE544FCA699DBDC5C576AEF3A"),
            "0xD2453Ae76C9A86AAe544fca699DbDC5c576aEf3A"
        );

        assert_eq!(
            to_check_sum_address("72220E84947C36118CDBC580454DFAA3B918CD97"),
            "0x72220e84947c36118cDbC580454DFaa3b918cD97"
        );

        assert_eq!(
            to_check_sum_address("50F92304C892D94A385CA6CE6CD6950CE9A36839"),
            "0x50f92304c892D94A385cA6cE6CD6950ce9A36839"
        );
    }

    #[test]
    fn test_generate_mac() {
        let result = generate_mac(
            &hex::decode("853e90e2612e676c251846103489b99e67494f6b7b2e808e3de2f39da5a7e48a")
                .unwrap(),
            &hex::decode("330fe82f1459a8c30fa454c7c3539c3a77c712273cf790ba3b498307f11da0ee")
                .unwrap(),
            &hex::decode("824d307c6bca39423df5e5a78abc0ab5").unwrap(),
        );

        assert_eq!(
            hex::encode(result),
            "b000a4ebbc855f6208df1b26e4dd84cfb9567f460f56857b73802f0f5b46aa69",
        );
    }
}
