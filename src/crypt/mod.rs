use self::{
    bcrypt::{bcrypt_crypt, BCRYPT_SALT_PREFIX},
    // des::des_crypt,
    md5_crypt::{md5_crypt, MD5_SALT_PREFIX},
    sha256_crypt::{sha256_crypt, SHA256_SALT_PREFIX},
    sha512_crypt::{sha512_crypt, SHA512_SALT_PREFIX},
};

mod bcrypt;
mod md5_crypt;
pub mod salt;
mod sha256_crypt;
mod sha512_crypt;

const BINARY64: &[u8] = b"./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

pub(crate) fn crypt(key: &[u8], salt: &[u8]) -> Option<String> {
    if salt.starts_with(MD5_SALT_PREFIX) {
        md5_crypt(key, salt)
    } else if salt.starts_with(BCRYPT_SALT_PREFIX) {
        bcrypt_crypt(key, salt)
    } else if salt.starts_with(SHA256_SALT_PREFIX) {
        sha256_crypt(key, salt)
    } else if salt.starts_with(SHA512_SALT_PREFIX) {
        sha512_crypt(key, salt)
    } else {
        // des_crypt(key, salt)
        unimplemented!("DES is no longer supported, use a modern hash instead.")
    }
}
