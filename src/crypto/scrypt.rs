use std::error::Error;

use scrypt::{scrypt, Params};

pub fn get_derived_key(
    password: &[u8],
    salt: &[u8],
    n: u32,
    r: u32,
    p: u32,
    dk_len: usize,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let mut output = vec![0u8; dk_len];

    let params = Params::new((n as f32).log2() as u8, r, p)?;
    scrypt(password, salt, &params, &mut output).unwrap();

    Ok(output.to_vec())
}
