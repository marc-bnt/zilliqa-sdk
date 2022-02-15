use bech32::FromBase32;
use std::error::Error;

const HRP: &str = "zil";

pub fn from_bech32_addr(address: &str) -> Result<String, Box<dyn Error>> {
    let (hrp, data, _) = bech32::decode(address)?;

    if hrp != HRP {
        return Err(String::from("expected hrp to be zil").into());
    }

    let conv = Vec::<u8>::from_base32(&data)?;

    Ok(hex::encode(&conv))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_from_bech32_addr() {
        let addr = from_bech32_addr("zil1fwh4ltdguhde9s7nysnp33d5wye6uqpugufkz7").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "4BAF5FADA8E5DB92C3D3242618C5B47133AE003C"
        );

        let addr = from_bech32_addr("zil1gjpxry26srx7n008c7nez6zjqrf6p06wur4x3m").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "448261915A80CDE9BDE7C7A791685200D3A0BF4E"
        );

        let addr = from_bech32_addr("zil1mmgzlktelsh9tspy80f02t0sytzq4ks79zdnkk").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "DED02FD979FC2E55C0243BD2F52DF022C40ADA1E"
        );

        let addr = from_bech32_addr("zil1z0cxucpf004x50zq9ahkf3qk56e3ukrwaty4g8").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "13F06E60297BEA6A3C402F6F64C416A6B31E586E"
        );

        let addr = from_bech32_addr("zil1r2gvy5c8c0x8r9v2s0azzw3rvtv9nnenynd33g").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "1A90C25307C3CC71958A83FA213A2362D859CF33"
        );

        let addr = from_bech32_addr("zil1vfdt467c0khf4vfg7we6axtg3qfan3wlf9yc6y").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "625ABAEBD87DAE9AB128F3B3AE99688813D9C5DF"
        );

        let addr = from_bech32_addr("zil1x6argztlscger3yvswwfkx5ttyf0tq703v7fre").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "36BA34097F861191C48C839C9B1A8B5912F583CF"
        );

        let addr = from_bech32_addr("zil16fzn4emvn2r24e2yljnfnk7ut3tk4me6qx08ed").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "D2453AE76C9A86AAE544FCA699DBDC5C576AEF3A"
        );

        let addr = from_bech32_addr("zil1wg3qapy50smprrxmckqy2n065wu33nvh35dn0v").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "72220E84947C36118CDBC580454DFAA3B918CD97"
        );

        let addr = from_bech32_addr("zil12rujxpxgjtv55wzu5m8xe454pn56x6pedpl554").unwrap();
        assert_eq!(
            addr.to_uppercase(),
            "50F92304C892D94A385CA6CE6CD6950CE9A36839"
        );

        let addr = from_bech32_addr("zil1r5verznnwvrzrz6uhveyrlxuhkvccwnju4aehf").unwrap();
        assert_eq!(
            addr.to_lowercase(),
            "1d19918a737306218b5cbb3241fcdcbd998c3a72"
        );

        let addr = from_bech32_addr("zil1tawmrsvvehn8u5fm0aawsg89dy25ja46ndsrhq").unwrap();
        assert_eq!(
            addr.to_lowercase(),
            "5f5db1c18ccde67e513b7f7ae820e569154976ba"
        );
    }
}
