use std::error::Error;

use pbkdf2::{
    password_hash::{PasswordHasher, Salt},
    Params, Pbkdf2,
};

pub struct PBKDF2Wrapper;

impl PBKDF2Wrapper {
    pub fn new() -> Self {
        Self
    }

    pub fn get_derived_key(
        &self,
        password: &[u8],
        salt: &[u8],
        iteration_count: u32,
        key_size: usize,
    ) -> Result<Vec<u8>, Box<dyn Error>> {
        let salt = String::from_utf8(salt.into())?;
        let salt = Salt::new(&salt)?;

        let params = Params {
            rounds: iteration_count,
            output_length: key_size,
        };

        let hash = Pbkdf2.hash_password_customized(password, None, None, params, salt)?;

        Ok(hash.hash.unwrap().as_bytes().into())
    }
}
